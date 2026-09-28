import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "node:crypto";
import Database from "better-sqlite3";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import crypto from "node:crypto";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||"change-this-in-production";
const db=new Database(process.env.DB_PATH||path.join(__dirname,"data.sqlite"));
const upload=multer({dest:path.join(__dirname,"uploads"),limits:{fileSize:10*1024*1024}});

fs.mkdirSync(path.join(__dirname,"uploads"),{recursive:true});
app.use(express.json({limit:"1mb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces(
 id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,owner_id INTEGER NOT NULL,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans(
 id INTEGER PRIMARY KEY AUTOINCREMENT,workspace_id INTEGER NOT NULL,filename TEXT NOT NULL,row_count INTEGER NOT NULL,exception_count INTEGER NOT NULL,created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id INTEGER NOT NULL,type TEXT NOT NULL,severity TEXT NOT NULL,customer TEXT,reference TEXT,amount REAL DEFAULT 0,reason TEXT,action TEXT,status TEXT NOT NULL DEFAULT 'OPEN',note TEXT DEFAULT '',created_at TEXT NOT NULL,resolved_at TEXT
);
`);

const now=()=>new Date().toISOString();
const hash=p=>crypto.createHash("sha256").update(p).digest("hex");
function token(u){return jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
 try{const t=req.cookies.bed_session;if(!t)throw 0;req.user=jwt.verify(t,JWT_SECRET);next();}
 catch{res.status(401).json({error:"Authentication required"});}
}
function csv(text){
 const lines=text.split(/\r?\n/).filter(x=>x.trim());
 if(!lines.length)return [];
 const parse=l=>{let a=[],cur="",q=false;for(let i=0;i<l.length;i++){let c=l[i];if(c==='"'){if(q&&l[i+1]==='"'){cur+='"';i++;}else q=!q;}else if(c===','&&!q){a.push(cur);cur="";}else cur+=c;}a.push(cur);return a};
 const h=parse(lines[0]).map(x=>x.trim().toLowerCase());
 return lines.slice(1).map(l=>{const a=parse(l),o={};h.forEach((k,i)=>o[k]=a[i]??"");return o});
}
const num=x=>Number(String(x??"").replace(/[£,]/g,""))||0;
function find(o,keys){for(const k of keys){const h=Object.keys(o).find(x=>x.replace(/[^a-z]/g,"").includes(k));if(h)return o[h];}return "";}
function detect(rows){
 const out=[],refs=new Map();
 rows.forEach((r,i)=>{const ref=find(r,["invoiceno","invoicenumber","reference","invoice"]);if(ref){const k=ref.toLowerCase().replace(/[\s_-]/g,"");if(!refs.has(k))refs.set(k,[]);refs.get(k).push(i);}});
 refs.forEach(ix=>{if(ix.length>1)ix.slice(1).forEach(i=>out.push({
   type:"Duplicate",severity:"HIGH",customer:find(rows[i],["customer","client","supplier"]),
   reference:find(rows[i],["invoiceno","reference","invoice"]),amount:num(find(rows[i],["total","amount","value"])),
   reason:"The invoice reference matches another record.",action:"Verify the source document before posting."
 }))});
 rows.forEach(r=>{const total=num(find(r,["invoicetotal","total","amount","value"])),paid=num(find(r,["amountpaid","paid","payment"])),credit=num(find(r,["creditnote","credit"])),due=Math.max(0,total-paid-credit);
 if(due>.01)out.push({type:"Payment",severity:paid===0?"HIGH":"MEDIUM",customer:find(r,["customer","client","supplier"]),reference:find(r,["invoiceno","reference","invoice"]),amount:due,reason:paid===0?"No payment recorded against this invoice.":"The invoice is only partially paid.",action:paid===0?"Contact customer / follow up collection.":"Reconcile the remaining balance."});
 });
 return out;
}

app.post("/api/signup",(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 if(!email||password.length<8)return res.status(400).json({error:"Use a valid email and an 8+ character password."});
 try{
  const info=db.prepare("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)").run(email,hash(password));
  const wid=db.prepare("INSERT INTO workspaces(name,owner_id,created_at) VALUES(?,?,?)").run("My Business",info.lastInsertRowid,now()).lastInsertRowid;
  const u={id:Number(info.lastInsertRowid),email};res.cookie("bed_session",token(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
  res.json({user:u,workspaceId:wid});
 }catch{res.status(409).json({error:"An account with that email already exists."});}
});
app.post("/api/login",(req,res)=>{
 const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u||hash(password)!==u.password_hash)return res.status(401).json({error:"Invalid email or password."});
 res.cookie("bed_session",token(u),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*864e5});
 res.json({user:{id:u.id,email:u.email}});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("bed_session");res.json({ok:true});});
app.get("/api/me",auth,(req,res)=>{
 const ws=db.prepare("SELECT * FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 res.json({user:req.user,workspace:ws});
});
app.post("/api/scans",auth,upload.single("file"),(req,res)=>{
 if(!req.file)return res.status(400).json({error:"CSV file required."});
 const ws=db.prepare("SELECT * FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 if(!ws)return res.status(404).json({error:"Workspace not found."});
 try{
  const text=fs.readFileSync(req.file.path,"utf8"),rows=csv(text),issues=detect(rows);
  const scan=db.prepare("INSERT INTO scans(workspace_id,filename,row_count,exception_count,created_at) VALUES(?,?,?,?,?)").run(ws.id,req.file.originalname,rows.length,issues.length,now());
  const ins=db.prepare("INSERT INTO exceptions(scan_id,type,severity,customer,reference,amount,reason,action,created_at) VALUES(?,?,?,?,?,?,?,?,?)");
  const tx=db.transaction(list=>list.forEach(x=>ins.run(scan.lastInsertRowid,x.type,x.severity,x.customer,x.reference,x.amount,x.reason,x.action,now())));
  tx(issues);fs.unlinkSync(req.file.path);
  res.json({scanId:Number(scan.lastInsertRowid),rows:rows.length,exceptions:issues.length});
 }catch(e){try{fs.unlinkSync(req.file.path)}catch{};res.status(400).json({error:"Could not read that CSV."});}
});
app.get("/api/scans",auth,(req,res)=>{
 const ws=db.prepare("SELECT * FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 const scans=db.prepare("SELECT * FROM scans WHERE workspace_id=? ORDER BY id DESC LIMIT 50").all(ws.id);
 res.json({scans});
});
app.get("/api/exceptions",auth,(req,res)=>{
 const ws=db.prepare("SELECT id FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 const rows=db.prepare(`SELECT e.* FROM exceptions e JOIN scans s ON s.id=e.scan_id WHERE s.workspace_id=? AND e.status='OPEN' ORDER BY CASE e.severity WHEN 'HIGH' THEN 0 ELSE 1 END,e.id DESC`).all(ws.id);
 res.json({exceptions:rows});
});
app.patch("/api/exceptions/:id",auth,(req,res)=>{
 const status=req.body.status==="RESOLVED"?"RESOLVED":req.body.status==="IGNORED"?"IGNORED":null;
 if(!status)return res.status(400).json({error:"Invalid status."});
 const ws=db.prepare("SELECT id FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 const x=db.prepare("SELECT e.id FROM exceptions e JOIN scans s ON s.id=e.scan_id WHERE e.id=? AND s.workspace_id=?").get(req.params.id,ws.id);
 if(!x)return res.status(404).json({error:"Exception not found."});
 db.prepare("UPDATE exceptions SET status=?,resolved_at=? WHERE id=?").run(status,now(),x.id);
 res.json({ok:true});
});
app.patch("/api/exceptions/:id/note",auth,(req,res)=>{
 const ws=db.prepare("SELECT id FROM workspaces WHERE owner_id=? ORDER BY id LIMIT 1").get(req.user.id);
 const x=db.prepare("SELECT e.id FROM exceptions e JOIN scans s ON s.id=e.scan_id WHERE e.id=? AND s.workspace_id=?").get(req.params.id,ws.id);
 if(!x)return res.status(404).json({error:"Exception not found."});
 db.prepare("UPDATE exceptions SET note=? WHERE id=?").run(String(req.body.note||"").slice(0,2000),x.id);
 res.json({ok:true});
});
app.listen(PORT,()=>console.log(`Business Exception Detector running on :${PORT}`));