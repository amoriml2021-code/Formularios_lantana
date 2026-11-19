'use strict';
// Controle de Formulários – servidor sem dependências (Node 22+). Banco: SQLite embutido.
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000,DBFILE=process.env.DB_FILE||path.join(__dirname,'data','controle.db');
fs.mkdirSync(path.dirname(DBFILE),{recursive:true});
const db=new DatabaseSync(DBFILE);
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS docs(col TEXT,id TEXT,data TEXT NOT NULL,PRIMARY KEY(col,id));
CREATE TABLE IF NOT EXISTS users(login TEXT PRIMARY KEY,salt TEXT,hash TEXT,perfil TEXT NOT NULL,empId TEXT,ativo INTEGER DEFAULT 1,ultimo TEXT,falhas INTEGER DEFAULT 0,bloq_ate INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,login TEXT,exp INTEGER);
CREATE TABLE IF NOT EXISTS audit(n INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,quem TEXT,acao TEXT,det TEXT);
CREATE TRIGGER IF NOT EXISTS imut_upd BEFORE UPDATE ON docs WHEN OLD.col IN ('launches','attendance') BEGIN SELECT RAISE(ABORT,'Registro confirmado: bloqueado'); END;
CREATE TRIGGER IF NOT EXISTS imut_del BEFORE DELETE ON docs WHEN OLD.col IN ('launches','attendance') BEGIN SELECT RAISE(ABORT,'Registro confirmado: bloqueado'); END;
CREATE TRIGGER IF NOT EXISTS aud_upd BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'Auditoria imutável'); END;
CREATE TRIGGER IF NOT EXISTS aud_del BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'Auditoria imutável'); END;`);
const q=(s,...a)=>db.prepare(s).all(...a),q1=(s,...a)=>db.prepare(s).get(...a),run=(s,...a)=>db.prepare(s).run(...a);
const log=(quem,acao,det)=>run('INSERT INTO audit(ts,quem,acao,det) VALUES(?,?,?,?)',new Date().toISOString(),quem||'-',acao,String(det||'').slice(0,500));
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
function setPw(login,pw){const salt=crypto.randomBytes(16).toString('hex');run('UPDATE users SET salt=?,hash=? WHERE login=?',salt,hashPw(pw,salt),login)}
function newUser(login,pw,perfil,empId){run('INSERT INTO users(login,perfil,empId) VALUES(?,?,?)',login,perfil,empId||null);setPw(login,pw)}
if(!q1('SELECT 1 x FROM users')){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(6).toString('base64url');
  newUser('admin',pw,'admin');log('sistema','admin criado','');console.log(`\n>>> Administrador criado: usuário "admin"  senha "${pw}"  (troque após o primeiro acesso)\n`)}
const COLS=['roles','forms','emps','launches','attendance','rectifications'],PERFIS=['admin','gestor','consulta','colaborador'];
const SIT=['Presente','Ausente','Férias','Afastado','Folga'],uid=()=>crypto.randomBytes(8).toString('hex');
const send=(res,c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...h});res.end(JSON.stringify(o))};
const err=(res,c,m)=>send(res,c,{erro:m});
const body=req=>new Promise((ok,ko)=>{let b='';req.on('data',d=>{b+=d;if(b.length>1e6){ko(new Error('grande'));req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch(e){ko(e)}})});
function who(req){const m=/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(!m)return null;
  const s=q1('SELECT * FROM sessions WHERE token=? AND exp>?',m[1],Date.now());if(!s)return null;
  const u=q1('SELECT login,perfil,empId,ativo FROM users WHERE login=?',s.login);return u&&u.ativo?{...u,token:m[1]}:null}
const own=(u,col,id)=>u.perfil!=='colaborador'||(col==='emps'?id===u.empId:id.startsWith(u.empId+'_'));
const eff=id=>{const l=q1("SELECT data FROM docs WHERE col='launches' AND id=?",id);if(!l)return null;
  const r=q1("SELECT data FROM docs WHERE col='rectifications' AND id=?",id);return r?JSON.parse(r.data).novo:JSON.parse(l.data).status};
async function api(req,res,u,url){
  const p=url.pathname.split('/').slice(2),m=req.method;
  if(p[0]==='me')return send(res,200,{login:u.login,perfil:u.perfil,empId:u.empId});
  if(p[0]==='backup'&&u.perfil==='admin'){const t=path.join(path.dirname(DBFILE),'bkp_'+Date.now()+'.db');db.exec(`VACUUM INTO '${t}'`);
    const b=fs.readFileSync(t);fs.unlinkSync(t);log(u.login,'backup','');
    res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':'attachment; filename="backup-controle.db"'});return res.end(b)}
  if(p[0]==='users'){if(u.perfil!=='admin'){log(u.login,'acesso_negado','users');return err(res,403,'Somente administrador.')}
    if(m==='GET')return send(res,200,{users:q('SELECT login,perfil,empId,ativo,ultimo FROM users ORDER BY login')});
    const b=await body(req);
    if(m==='POST'){if(!/^[\w.@-]{3,60}$/.test(b.login||'')||(b.senha||'').length<8||!PERFIS.includes(b.perfil))return err(res,400,'Login (3+), senha (8+) e perfil válidos são obrigatórios.');
      if(q1('SELECT 1 x FROM users WHERE login=?',b.login))return err(res,409,'Login já existe.');
      newUser(b.login,b.senha,b.perfil,b.empId);log(u.login,'usuario criado',b.login+' '+b.perfil);return send(res,200,{ok:1})}
    if(m==='PATCH'&&p[1]){const t=q1('SELECT * FROM users WHERE login=?',p[1]);if(!t)return err(res,404,'Usuário não encontrado.');
      if(b.ativo===false&&t.login===u.login)return err(res,400,'Você não pode bloquear a si mesmo.');
      if(typeof b.ativo==='boolean')run('UPDATE users SET ativo=?,falhas=0,bloq_ate=0 WHERE login=?',+b.ativo,t.login);
      if(b.senha){if(b.senha.length<8)return err(res,400,'Senha com 8+ caracteres.');setPw(t.login,b.senha)}
      if(b.perfil&&PERFIS.includes(b.perfil))run('UPDATE users SET perfil=? WHERE login=?',b.perfil,t.login);
      if('empId'in b)run('UPDATE users SET empId=? WHERE login=?',b.empId||null,t.login);
      log(u.login,'usuario alterado',t.login+' '+Object.keys(b).filter(k=>k!=='senha').join(',')+(b.senha?' senha-redefinida':''));return send(res,200,{ok:1})}}
  if(p[0]==='audit'&&m==='GET'&&u.perfil==='admin')return send(res,200,{audit:q('SELECT * FROM audit ORDER BY n DESC LIMIT 500')});
  if(p[0]==='c'&&COLS.includes(p[1])){const col=p[1],id=p[2];
    if(m==='GET'&&!id){const docs={};for(const r of q('SELECT id,data FROM docs WHERE col=?',col))if(own(u,col,r.id))docs[r.id]=JSON.parse(r.data);return send(res,200,{docs})}
    const deny=()=>{log(u.login,'acesso_negado',m+' '+url.pathname);return err(res,403,'Sem permissão.')};
    const b=await body(req),adm=u.perfil==='admin',ges=adm||u.perfil==='gestor';
    if(['roles','forms','emps'].includes(col)){if(!adm)return deny();
      if(m==='POST'){const i=uid();run('INSERT INTO docs VALUES(?,?,?)',col,i,JSON.stringify(b));log(u.login,'cadastro '+col,JSON.stringify(b));return send(res,200,{id:i})}
      if(m==='PUT'&&id){run('INSERT OR REPLACE INTO docs VALUES(?,?,?)',col,id,JSON.stringify(b));log(u.login,'edição '+col,id);return send(res,200,{ok:1})}
      if(m==='PATCH'&&id){const r=q1('SELECT data FROM docs WHERE col=? AND id=?',col,id);if(!r)return err(res,404,'Não encontrado.');
        run('UPDATE docs SET data=? WHERE col=? AND id=?',JSON.stringify({...JSON.parse(r.data),...b}),col,id);log(u.login,'edição '+col,id+' '+JSON.stringify(b));return send(res,200,{ok:1})}}
    if(col==='rectifications'&&m==='PUT'&&id){if(!adm)return deny();
      const ant=eff(id);if(!ant)return err(res,404,'Lançamento inexistente.');
      if(!['F','N'].includes(b.novo)||(b.just||'').trim().length<5)return err(res,400,'Justificativa (5+ caracteres) e novo valor são obrigatórios.');
      run('INSERT OR REPLACE INTO docs VALUES(?,?,?)',col,id,JSON.stringify({id,anterior:ant,novo:b.novo,just:b.just.trim(),por:u.login,ts:new Date().toISOString()}));
      log(u.login,'retificação',`${id} ${ant}→${b.novo} | ${b.just}`);return send(res,200,{ok:1})}
    if(m==='POST'&&p[0]==='c'&&id==='claim'){return err(res,400,'use /api/claim')}
  }
  if(p[0]==='claim'&&m==='POST'&&COLS.includes(p[1])&&p[2]){const col=p[1],id=p[2];
    if(!['launches','attendance'].includes(col)||!['admin','gestor'].includes(u.perfil)){log(u.login,'acesso_negado','claim '+url.pathname);return err(res,403,'Sem permissão para lançar.')}
    const b=await body(req),emp=q1("SELECT data FROM docs WHERE col='emps' AND id=?",b.emp);
    if(!emp||JSON.parse(emp.data).ativo===false||!/^\d{4}-\d\d-\d\d$/.test(b.ds||''))return err(res,400,'Dados inválidos.');
    let d;if(col==='launches'){if(id!==`${b.emp}_${b.form}_${b.ds}`||!['F','N'].includes(b.status)||!q1("SELECT 1 x FROM docs WHERE col='forms' AND id=?",b.form))return err(res,400,'Dados inválidos.');
      d={id,emp:b.emp,form:b.form,ds:b.ds,status:b.status,obs:String(b.obs||'').slice(0,500),roleNome:String(b.roleNome||'').slice(0,100)}}
    else{if(id!==`${b.emp}_${b.ds}`||!SIT.includes(b.sit))return err(res,400,'Dados inválidos.');d={emp:b.emp,ds:b.ds,sit:b.sit}}
    d.por=u.login;d.ts=new Date().toISOString();
    try{run('INSERT INTO docs VALUES(?,?,?)',col,id,JSON.stringify(d))}catch(e){log(u.login,'duplicidade_bloqueada',col+' '+id);return err(res,409,'Este formulário já possui um lançamento confirmado para este colaborador nesta data. Registro bloqueado.')}
    log(u.login,'lançamento '+col,id+' '+(d.status||d.sit));return send(res,200,{ok:1})}
  if(p[0]==='c'&&p[1]==='audit')return send(res,200,{ok:1}); // auditoria é gravada só pelo servidor
  err(res,404,'Rota inexistente.')}
http.createServer(async(req,res)=>{try{
  const url=new URL(req.url,'http://x');
  if(url.pathname==='/api/login'&&req.method==='POST'){const b=await body(req),t=q1('SELECT * FROM users WHERE login=?',String(b.login||''));
    if(t&&t.bloq_ate>Date.now())return err(res,429,'Muitas tentativas. Aguarde 5 minutos.');
    const ok=t&&t.ativo&&crypto.timingSafeEqual(Buffer.from(hashPw(String(b.senha||''),t.salt),'hex'),Buffer.from(t.hash,'hex'));
    if(!ok){if(t){const f=t.falhas+1;run('UPDATE users SET falhas=?,bloq_ate=? WHERE login=?',f%5?f:0,f%5?0:Date.now()+3e5,t.login)}log(t?t.login:String(b.login||'?').slice(0,40),'login_negado',t&&!t.ativo?'usuário bloqueado':'');return err(res,401,'Usuário ou senha inválidos.')}
    const tk=crypto.randomBytes(32).toString('hex');run('INSERT INTO sessions VALUES(?,?,?)',tk,t.login,Date.now()+8*36e5);
    run('UPDATE users SET falhas=0,ultimo=? WHERE login=?',new Date().toISOString(),t.login);log(t.login,'login','');
    return send(res,200,{ok:1},{'Set-Cookie':`sid=${tk}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.HTTPS?'; Secure':''}`})}
  if(url.pathname.startsWith('/api/')){const u=who(req);if(!u)return err(res,401,'Não autenticado.');
    if(url.pathname==='/api/logout'){run('DELETE FROM sessions WHERE token=?',u.token);return send(res,200,{ok:1})}
    return await api(req,res,u,url)}
  if(url.pathname==='/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'public','index.html')))}
  err(res,404,'Não encontrado.')
}catch(e){console.error(e);if(!res.headersSent)err(res,500,'Erro interno.')}}).listen(PORT,()=>console.log('Servidor em http://localhost:'+PORT));
