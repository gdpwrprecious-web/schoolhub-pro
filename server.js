const express=require('express');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const multer=require('multer');
const path=require('path');
const fs=require('fs');
const crypto=require('crypto');
const dotenv=require('dotenv');
const passport=require('passport');
const GoogleStrategy=require('passport-google-oauth20').Strategy;
dotenv.config();

const app=express();
const PORT=process.env.PORT||3000;
const ROOT=__dirname;
const DATA=path.join(ROOT,'data');
const UP=path.join(ROOT,'uploads');
for(const d of [DATA,path.join(UP,'profiles'),path.join(UP,'schools')])fs.mkdirSync(d,{recursive:true});
const files={users:'users.json',schools:'schools.json',subjects:'subjects.json',announcements:'announcements.json',exams:'exams.json',questions:'questions.json',results:'results.json'};
const read=k=>{const p=path.join(DATA,files[k]);try{return JSON.parse(fs.readFileSync(p,'utf8')||'[]')}catch{return []}};
const write=(k,v)=>fs.writeFileSync(path.join(DATA,files[k]),JSON.stringify(v,null,2));
const uid=()=>crypto.randomUUID();
const now=()=>new Date().toISOString();
const safe=u=>u&&{id:u.id,fullName:u.fullName,username:u.username,email:u.email,role:u.role,schoolId:u.schoolId,profilePicture:u.profilePicture||'',active:u.active!==false,createdAt:u.createdAt};

app.use(express.json({limit:'5mb'}));
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||'change-this-secret',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*864e5}}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/uploads',express.static(UP));
app.use(express.static(path.join(ROOT,'public')));

function auth(req,res,next){
  if(!req.session.userId)return res.status(401).json({error:'Authentication required'});
  const u=read('users').find(x=>x.id===req.session.userId);
  if(!u||u.active===false)return res.status(401).json({error:'Account inactive'});
  req.user=u;next();
}
function role(...roles){return (req,res,next)=>{if(!roles.includes(req.user.role))return res.status(403).json({error:'Permission denied'});next()}}
function schoolScope(req,obj){return req.user.role==='superadmin'||obj.schoolId===req.user.schoolId}
function uploadFor(folder){
  const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,path.join(UP,folder)),filename:(req,file,cb)=>cb(null,uid()+path.extname(file.originalname).toLowerCase())});
  return multer({storage,limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>cb(null,/^image\/(png|jpeg|webp)$/.test(file.mimetype))});
}
const profileUpload=uploadFor('profiles'),logoUpload=uploadFor('schools');
const schoolOf=id=>read('schools').find(s=>s.id===id)||null;
const userOf=id=>read('users').find(u=>u.id===id)||null;
const subjectOf=id=>read('subjects').find(s=>s.id===id)||null;
const examOf=id=>read('exams').find(e=>e.id===id)||null;
const questionsOf=id=>read('questions').filter(q=>q.examId===id);

app.get('/api/health',(req,res)=>res.json({ok:true,version:'3.0.0',features:['multi-school','teacher-dashboard','student-dashboard','cbt-arena','results']}));
app.get('/api/me',auth,(req,res)=>res.json({user:safe(req.user),school:req.user.schoolId?schoolOf(req.user.schoolId):null}));

app.post('/api/register',async(req,res)=>{
  const {schoolName,motto,fullName,username,email,password}=req.body;
  if(!schoolName||!fullName||!username||!email||!password)return res.status(400).json({error:'All required fields must be supplied'});
  let users=read('users');
  if(users.some(u=>u.email?.toLowerCase()===email.toLowerCase()||u.username?.toLowerCase()===username.toLowerCase()))return res.status(409).json({error:'Username or email already exists'});
  let schools=read('schools');
  const school={id:uid(),name:schoolName,motto:motto||'',logo:'',primaryColor:'#2563eb',secondaryColor:'#16a34a',theme:'light',active:true,createdAt:now()};
  schools.push(school);write('schools',schools);
  const user={id:uid(),fullName,username,email:email.toLowerCase(),passwordHash:await bcrypt.hash(password,10),role:'school_admin',schoolId:school.id,active:true,provider:'local',createdAt:now()};
  users.push(user);write('users',users);req.session.userId=user.id;res.json({user:safe(user),school});
});

app.post('/api/login',async(req,res)=>{
  const identifier=String(req.body.identifier||'').trim();
  const u=read('users').find(x=>(x.email===identifier.toLowerCase()||x.username===identifier)&&x.active!==false);
  if(!u||!u.passwordHash||!(await bcrypt.compare(req.body.password||'',u.passwordHash)))return res.status(401).json({error:'Invalid login details'});
  req.session.userId=u.id;
  res.json({user:safe(u),redirect:u.role==='student'?'/student.html':u.role==='teacher'?'/teacher.html':'/admin.html'});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.put('/api/school/branding',auth,role('school_admin','superadmin'),(req,res)=>{
  const id=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;let schools=read('schools');const s=schools.find(x=>x.id===id);
  if(!s)return res.status(404).json({error:'School not found'});
  for(const k of ['name','motto','primaryColor','secondaryColor','theme'])if(req.body[k]!=null)s[k]=String(req.body[k]);
  write('schools',schools);res.json({school:s});
});
app.post('/api/school/logo',auth,role('school_admin','superadmin'),logoUpload.single('logo'),(req,res)=>{
  const id=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;let schools=read('schools');const s=schools.find(x=>x.id===id);
  if(!s||!req.file)return res.status(400).json({error:'School or logo missing'});s.logo='/uploads/schools/'+req.file.filename;write('schools',schools);res.json({school:s});
});
app.post('/api/profile-picture',auth,profileUpload.single('photo'),(req,res)=>{if(!req.file)return res.status(400).json({error:'Image missing'});let users=read('users');const u=users.find(x=>x.id===req.user.id);u.profilePicture='/uploads/profiles/'+req.file.filename;write('users',users);res.json({user:safe(u)});});
app.get('/api/school',auth,(req,res)=>res.json({school:schoolOf(req.user.schoolId)}));

// Users
app.get('/api/users',auth,role('school_admin','superadmin'),(req,res)=>{let users=read('users');if(req.user.role!=='superadmin')users=users.filter(u=>u.schoolId===req.user.schoolId);res.json(users.map(safe));});
app.post('/api/users',auth,role('school_admin','superadmin'),async(req,res)=>{
  const {fullName,username,email,password,role:ur}=req.body;
  if(!fullName||!username||!email||!password||!['teacher','student','school_admin'].includes(ur))return res.status(400).json({error:'Invalid user data'});
  let users=read('users');if(users.some(u=>u.email===email.toLowerCase()||u.username===username))return res.status(409).json({error:'User exists'});
  const schoolId=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;if(!schoolId)return res.status(400).json({error:'schoolId required'});
  if(!schoolOf(schoolId))return res.status(400).json({error:'School not found'});
  const u={id:uid(),fullName,username,email:email.toLowerCase(),passwordHash:await bcrypt.hash(password,10),role:ur,schoolId,active:true,provider:'local',createdAt:now()};users.push(u);write('users',users);res.json({user:safe(u)});
});
app.put('/api/users/:id',auth,role('school_admin','superadmin'),async(req,res)=>{let users=read('users');const u=users.find(x=>x.id===req.params.id);if(!u||!schoolScope(req,u))return res.status(404).json({error:'User not found'});for(const k of ['fullName','username','email','active'])if(req.body[k]!=null)u[k]=req.body[k];if(req.body.role&&['teacher','student','school_admin'].includes(req.body.role))u.role=req.body.role;if(req.body.password)u.passwordHash=await bcrypt.hash(req.body.password,10);write('users',users);res.json({user:safe(u)});});
app.delete('/api/users/:id',auth,role('school_admin','superadmin'),(req,res)=>{let users=read('users');const u=users.find(x=>x.id===req.params.id);if(!u||!schoolScope(req,u))return res.status(404).json({error:'User not found'});users=users.filter(x=>x.id!==u.id);write('users',users);res.json({ok:true});});

// Summary / teacher and student dashboard data
app.get('/api/admin/summary',auth,role('school_admin','superadmin'),(req,res)=>{
  const us=req.user.role==='superadmin'?read('users'):read('users').filter(u=>u.schoolId===req.user.schoolId);
  const ss=req.user.role==='superadmin'?read('schools'):read('schools').filter(s=>s.id===req.user.schoolId);
  res.json({students:us.filter(u=>u.role==='student').length,teachers:us.filter(u=>u.role==='teacher').length,admins:us.filter(u=>u.role==='school_admin').length,schools:ss.length,subjects:read('subjects').filter(x=>req.user.role==='superadmin'||x.schoolId===req.user.schoolId).length,exams:read('exams').filter(x=>req.user.role==='superadmin'||x.schoolId===req.user.schoolId).length,results:read('results').filter(x=>req.user.role==='superadmin'||x.schoolId===req.user.schoolId).length});
});
app.get('/api/teacher/summary',auth,role('teacher','school_admin','superadmin'),(req,res)=>{
  const sid=req.user.schoolId;
  const exams=read('exams').filter(e=>e.schoolId===sid);
  const results=read('results').filter(r=>r.schoolId===sid);
  const students=read('users').filter(u=>u.schoolId===sid&&u.role==='student');
  const subjects=read('subjects').filter(s=>s.schoolId===sid);
  const published=exams.filter(e=>e.status==='published');
  const avg=results.length?Math.round(results.reduce((n,r)=>n+Number(r.percentage||0),0)/results.length*10)/10:0;
  res.json({subjects:subjects.length,exams:exams.length,published:published.length,students:students.length,submissions:results.length,average:avg,questions:read('questions').filter(q=>exams.some(e=>e.id===q.examId)).length});
});
app.get('/api/student/summary',auth,role('student'),(req,res)=>{
  const exams=read('exams').filter(e=>e.schoolId===req.user.schoolId&&e.status==='published');
  const results=read('results').filter(r=>r.schoolId===req.user.schoolId&&r.studentId===req.user.id);
  const done=new Set(results.map(r=>r.examId));
  const avg=results.length?Math.round(results.reduce((n,r)=>n+Number(r.percentage||0),0)/results.length*10)/10:0;
  res.json({available:exams.filter(e=>!done.has(e.id)).length,completed:results.length,average:avg,totalExams:exams.length});
});

// Subjects
app.get('/api/subjects',auth,(req,res)=>res.json(read('subjects').filter(x=>schoolScope(req,x))));
app.post('/api/subjects',auth,role('school_admin','teacher','superadmin'),(req,res)=>{const schoolId=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;if(!schoolId||!req.body.name)return res.status(400).json({error:'Name and school required'});let a=read('subjects');const x={id:uid(),schoolId,name:req.body.name,code:req.body.code||'',description:req.body.description||'',createdBy:req.user.id,createdAt:now()};a.push(x);write('subjects',a);res.json({subject:x});});
app.put('/api/subjects/:id',auth,role('school_admin','teacher','superadmin'),(req,res)=>{let a=read('subjects');const x=a.find(v=>v.id===req.params.id);if(!x||!schoolScope(req,x))return res.status(404).json({error:'Subject not found'});Object.assign(x,{name:req.body.name??x.name,code:req.body.code??x.code,description:req.body.description??x.description});write('subjects',a);res.json({subject:x});});
app.delete('/api/subjects/:id',auth,role('school_admin','superadmin'),(req,res)=>{let a=read('subjects');const x=a.find(v=>v.id===req.params.id);if(!x||!schoolScope(req,x))return res.status(404).json({error:'Subject not found'});write('subjects',a.filter(v=>v.id!==x.id));res.json({ok:true});});

// Announcements
app.get('/api/announcements',auth,(req,res)=>res.json(read('announcements').filter(x=>schoolScope(req,x)).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))));
app.post('/api/announcements',auth,role('school_admin','teacher','superadmin'),(req,res)=>{const schoolId=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;const x={id:uid(),schoolId,title:req.body.title,body:req.body.body,createdBy:req.user.id,createdAt:now()};if(!x.title||!x.body)return res.status(400).json({error:'Title and body required'});let a=read('announcements');a.push(x);write('announcements',a);res.json({announcement:x});});
app.delete('/api/announcements/:id',auth,role('school_admin','superadmin'),(req,res)=>{let a=read('announcements');const x=a.find(v=>v.id===req.params.id);if(!x||!schoolScope(req,x))return res.status(404).json({error:'Not found'});write('announcements',a.filter(v=>v.id!==x.id));res.json({ok:true});});

// CBT / Exams
app.get('/api/exams',auth,(req,res)=>{const exams=read('exams').filter(x=>schoolScope(req,x));res.json(exams.map(e=>({...e,subject:subjectOf(e.subjectId)?.name||'Unknown subject',questionCount:questionsOf(e.id).length,submissionCount:read('results').filter(r=>r.examId===e.id).length}))) });
app.get('/api/exams/:id',auth,(req,res)=>{const e=examOf(req.params.id);if(!e||!schoolScope(req,e))return res.status(404).json({error:'Exam not found'});res.json({...e,subject:subjectOf(e.subjectId),questionCount:questionsOf(e.id).length,submissionCount:read('results').filter(r=>r.examId===e.id).length});});
app.post('/api/exams',auth,role('school_admin','teacher','superadmin'),(req,res)=>{
  const schoolId=req.user.role==='superadmin'?req.body.schoolId:req.user.schoolId;
  const subject=read('subjects').find(s=>s.id===req.body.subjectId&&s.schoolId===schoolId);
  if(!subject)return res.status(400).json({error:'Invalid subject'});
  const e={id:uid(),schoolId,subjectId:subject.id,title:String(req.body.title||'Untitled CBT').trim(),duration:Number(req.body.duration)||30,instructions:req.body.instructions||'',status:req.body.status==='published'?'published':'draft',createdBy:req.user.id,createdAt:now()};
  if(!e.title)return res.status(400).json({error:'Exam title required'});
  let a=read('exams');a.push(e);write('exams',a);res.json({exam:e});
});
app.put('/api/exams/:id',auth,role('school_admin','teacher','superadmin'),(req,res)=>{let a=read('exams');const e=a.find(x=>x.id===req.params.id);if(!e||!schoolScope(req,e))return res.status(404).json({error:'Exam not found'});for(const k of ['title','instructions','status'])if(req.body[k]!=null)e[k]=req.body[k];if(req.body.duration!=null)e.duration=Math.max(1,Number(req.body.duration)||30);write('exams',a);res.json({exam:e});});
app.delete('/api/exams/:id',auth,role('school_admin','teacher','superadmin'),(req,res)=>{let a=read('exams');const e=a.find(x=>x.id===req.params.id);if(!e||!schoolScope(req,e))return res.status(404).json({error:'Exam not found'});write('exams',a.filter(x=>x.id!==e.id));write('questions',read('questions').filter(q=>q.examId!==e.id));write('results',read('results').filter(r=>r.examId!==e.id));res.json({ok:true});});

// Teacher question management
const normalizeQuestionInput=(body)=>{
  const options=Array.isArray(body.options)?body.options.map(v=>String(v).trim()).filter(Boolean):[];
  return {question:String(body.question||'').trim(),options,answer:Number(body.answer),points:Math.max(1,Number(body.points)||1),difficulty:String(body.difficulty||'medium').toLowerCase(),explanation:String(body.explanation||'').trim(),tags:String(body.tags||'').trim()};
};
app.get('/api/exams/:id/questions',auth,(req,res)=>{const e=examOf(req.params.id);if(!e||!schoolScope(req,e))return res.status(404).json({error:'Exam not found'});const qs=questionsOf(e.id);if(req.user.role==='student')return res.json(qs.map(({answer,...q})=>q));res.json(qs);});
app.get('/api/question-bank',auth,role('school_admin','teacher','superadmin'),(req,res)=>{
  const sid=req.user.role==='superadmin'?(req.query.schoolId||null):req.user.schoolId;
  const subjectId=String(req.query.subjectId||'');
  const difficulty=String(req.query.difficulty||'').toLowerCase();
  const tag=String(req.query.tag||'').toLowerCase();
  const search=String(req.query.search||'').toLowerCase();
  let qs=read('questions').filter(q=>(!sid||q.schoolId===sid));
  const exams=read('exams').filter(e=>(!sid||e.schoolId===sid));
  const examMap=new Map(exams.map(e=>[e.id,e]));
  qs=qs.filter(q=>{const e=examMap.get(q.examId);if(!e)return false;if(subjectId&&e.subjectId!==subjectId)return false;if(difficulty&&String(q.difficulty||'medium').toLowerCase()!==difficulty)return false;if(tag&&!String(q.tags||'').toLowerCase().split(',').map(x=>x.trim()).includes(tag))return false;if(search&&!((q.question||'').toLowerCase().includes(search)||(q.tags||'').toLowerCase().includes(search)||(e.title||'').toLowerCase().includes(search)))return false;return true;});
  res.json(qs.map(q=>{const e=examMap.get(q.examId);return {...q,examTitle:e?.title||'Unknown CBT',subject:subjectOf(e?.subjectId)?.name||'Unknown subject'};}));
});
app.post('/api/question-bank/bulk',auth,role('school_admin','teacher','superadmin'),(req,res)=>{
  const examId=String(req.body.examId||'');const e=examOf(examId);if(!e||!schoolScope(req,e))return res.status(404).json({error:'CBT not found'});
  if(!Array.isArray(req.body.questions)||!req.body.questions.length)return res.status(400).json({error:'Provide a questions array'});
  const created=[];for(const item of req.body.questions){const q=normalizeQuestionInput(item);if(!q.question||q.options.length<2||!Number.isInteger(q.answer)||q.answer<0||q.answer>=q.options.length)continue;created.push({id:uid(),examId:e.id,schoolId:e.schoolId,...q,createdAt:now(),createdBy:req.user.id});}
  if(!created.length)return res.status(400).json({error:'No valid questions found'});let a=read('questions');a.push(...created);write('questions',a);res.json({created:created.length,questions:created});
});
app.post('/api/exams/:id/questions',auth,role('school_admin','teacher','superadmin'),(req,res)=>{const e=examOf(req.params.id);if(!e||!schoolScope(req,e))return res.status(404).json({error:'Exam not found'});const q=normalizeQuestionInput(req.body);if(!q.question||q.options.length<2||!Number.isInteger(q.answer)||q.answer<0||q.answer>=q.options.length)return res.status(400).json({error:'Question, options and a valid answer are required'});const x={id:uid(),examId:e.id,schoolId:e.schoolId,...q,createdAt:now(),createdBy:req.user.id};let a=read('questions');a.push(x);write('questions',a);res.json({question:x});});
app.put('/api/questions/:id',auth,role('school_admin','teacher','superadmin'),(req,res)=>{let a=read('questions');const q=a.find(x=>x.id===req.params.id);if(!q||!schoolScope(req,q))return res.status(404).json({error:'Question not found'});const incoming=normalizeQuestionInput({...q,...req.body});if(!incoming.question||incoming.options.length<2||!Number.isInteger(incoming.answer)||incoming.answer<0||incoming.answer>=incoming.options.length)return res.status(400).json({error:'Question, options and a valid answer are required'});Object.assign(q,incoming);write('questions',a);res.json({question:q});});
app.delete('/api/questions/:id',auth,role('school_admin','teacher','superadmin'),(req,res)=>{let a=read('questions');const q=a.find(x=>x.id===req.params.id);if(!q||!schoolScope(req,q))return res.status(404).json({error:'Question not found'});write('questions',a.filter(x=>x.id!==q.id));res.json({ok:true});});

// Student CBT arena APIs
app.get('/api/exams/:id/take',auth,role('student'),(req,res)=>{
  const e=examOf(req.params.id);
  if(!e||e.schoolId!==req.user.schoolId||e.status!=='published')return res.status(404).json({error:'Exam unavailable'});
  if(read('results').some(r=>r.examId===e.id&&r.studentId===req.user.id))return res.status(409).json({error:'You already submitted this exam'});
  const qs=questionsOf(e.id).map(q=>({id:q.id,question:q.question,options:q.options,points:q.points}));
  res.json({exam:{id:e.id,title:e.title,duration:e.duration,instructions:e.instructions,subject:subjectOf(e.subjectId)?.name||''},questions:qs,serverTime:now()});
});
app.post('/api/exams/:id/submit',auth,role('student'),(req,res)=>{
  const e=examOf(req.params.id);
  if(!e||e.schoolId!==req.user.schoolId||e.status!=='published')return res.status(404).json({error:'Exam unavailable'});
  if(read('results').some(r=>r.examId===e.id&&r.studentId===req.user.id))return res.status(409).json({error:'You already submitted this exam'});
  const answers=req.body.answers&&typeof req.body.answers==='object'?req.body.answers:{};
  const qs=questionsOf(e.id);if(!qs.length)return res.status(400).json({error:'This CBT has no questions yet'});
  let score=0,total=0,answered=0;
  for(const q of qs){total+=Number(q.points)||1;if(answers[q.id]!==undefined&&answers[q.id]!==null&&answers[q.id]!=='')answered++;if(Number(answers[q.id])===Number(q.answer))score+=Number(q.points)||1;}
  const r={id:uid(),schoolId:e.schoolId,examId:e.id,studentId:req.user.id,score,total,percentage:total?Math.round(score/total*10000)/100:0,answered,totalQuestions:qs.length,answers,submittedAt:now()};let a=read('results');a.push(r);write('results',a);res.json({result:{...r,exam:e.title}});
});

// Results
app.get('/api/results',auth,(req,res)=>{
  let a=read('results').filter(r=>schoolScope(req,r));
  if(req.user.role==='student')a=a.filter(r=>r.studentId===req.user.id);
  res.json(a.map(r=>({...r,student:userOf(r.studentId)?.fullName||'Unknown',exam:examOf(r.examId)?.title||'Unknown',subject:subjectOf(examOf(r.examId)?.subjectId||'')?.name||'Unknown'})).sort((x,y)=>y.submittedAt.localeCompare(x.submittedAt)));
});
app.get('/api/results/:id',auth,(req,res)=>{const r=read('results').find(x=>x.id===req.params.id);if(!r||!schoolScope(req,r)||(req.user.role==='student'&&r.studentId!==req.user.id))return res.status(404).json({error:'Result not found'});const e=examOf(r.examId);res.json({...r,student:userOf(r.studentId)?.fullName||'Unknown',exam:e?.title||'Unknown',subject:subjectOf(e?.subjectId||'')?.name||'Unknown'});});

// Superadmin
app.get('/api/superadmin/schools',auth,role('superadmin'),(req,res)=>res.json(read('schools')));
app.post('/api/superadmin/schools',auth,role('superadmin'),(req,res)=>{if(!req.body.name)return res.status(400).json({error:'Name required'});let a=read('schools');const s={id:uid(),name:req.body.name,motto:req.body.motto||'',logo:'',primaryColor:'#2563eb',secondaryColor:'#16a34a',theme:'light',active:true,createdAt:now()};a.push(s);write('schools',a);res.json({school:s});});
app.put('/api/superadmin/schools/:id',auth,role('superadmin'),(req,res)=>{let a=read('schools');const s=a.find(x=>x.id===req.params.id);if(!s)return res.status(404).json({error:'School not found'});Object.assign(s,{name:req.body.name??s.name,motto:req.body.motto??s.motto,active:req.body.active??s.active});write('schools',a);res.json({school:s});});
app.get('/api/superadmin/all-users',auth,role('superadmin'),(req,res)=>res.json(read('users').map(safe)));
app.get('/api/platform-config',(req,res)=>res.json({googleConfigured:Boolean(process.env.GOOGLE_CLIENT_ID&&process.env.GOOGLE_CLIENT_SECRET&&process.env.GOOGLE_CALLBACK_URL)}));

if(process.env.GOOGLE_CLIENT_ID&&process.env.GOOGLE_CLIENT_SECRET&&process.env.GOOGLE_CALLBACK_URL){
  passport.use(new GoogleStrategy({clientID:process.env.GOOGLE_CLIENT_ID,clientSecret:process.env.GOOGLE_CLIENT_SECRET,callbackURL:process.env.GOOGLE_CALLBACK_URL},async(accessToken,refreshToken,profile,done)=>{
    try{let users=read('users');let email=profile.emails?.[0]?.value?.toLowerCase();let u=users.find(x=>x.providerId===profile.id||x.email===email);if(!u)return done(null,false,{message:'Google account must be linked to an existing school account by an administrator.'});u.provider='google';u.providerId=profile.id;u.profilePicture=u.profilePicture||profile.photos?.[0]?.value||'';write('users',users);done(null,u)}catch(e){done(e)}
  }));
  passport.serializeUser((u,done)=>done(null,u.id));passport.deserializeUser((id,done)=>done(null,read('users').find(u=>u.id===id)||false));
  app.get('/auth/google',passport.authenticate('google',{scope:['profile','email']}));
  app.get('/auth/google/callback',passport.authenticate('google',{failureRedirect:'/login.html?google=failed'}),(req,res)=>{req.session.userId=req.user.id;res.redirect(req.user.role==='student'?'/student.html':req.user.role==='teacher'?'/teacher.html':'/admin.html')});
}

app.get('*',(req,res)=>res.sendFile(path.join(ROOT,'public','index.html')));
app.listen(PORT,()=>console.log(`SchoolHub Pro v3 running on http://localhost:${PORT}`));
