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

/*
|--------------------------------------------------------------------------
| RAILWAY / PROXY
|--------------------------------------------------------------------------
| Railway sits behind a reverse proxy.
| Trusting the proxy allows secure session cookies to work correctly.
*/
app.set('trust proxy',1);

/*
|--------------------------------------------------------------------------
| PERSISTENT STORAGE
|--------------------------------------------------------------------------
| Railway:
| STORAGE_DIR=/app/storage
|
| Local:
| uses the project folder.
*/
const STORAGE_ROOT =
  process.env.STORAGE_DIR ||
  (process.env.NODE_ENV==='production'
    ? '/app/storage'
    : ROOT);

const DATA=path.join(STORAGE_ROOT,'data');
const UP=path.join(STORAGE_ROOT,'uploads');

for(const d of [
  DATA,
  path.join(UP,'profiles'),
  path.join(UP,'schools')
]){
  fs.mkdirSync(d,{recursive:true});
}

const files={
  users:'users.json',
  schools:'schools.json',
  subjects:'subjects.json',
  announcements:'announcements.json',
  exams:'exams.json',
  questions:'questions.json',
  results:'results.json'
};

const read=k=>{
  const p=path.join(DATA,files[k]);
  try{
    return JSON.parse(fs.readFileSync(p,'utf8')||'[]');
  }catch{
    return [];
  }
};

const write=(k,v)=>{
  const p=path.join(DATA,files[k]);
  fs.mkdirSync(path.dirname(p),{recursive:true});
  fs.writeFileSync(p,JSON.stringify(v,null,2));
};

const uid=()=>crypto.randomUUID();
const now=()=>new Date().toISOString();

const safe=u=>u&&{
  id:u.id,
  fullName:u.fullName,
  username:u.username,
  email:u.email,
  role:u.role,
  schoolId:u.schoolId,
  profilePicture:u.profilePicture||'',
  active:u.active!==false,
  createdAt:u.createdAt
};

/*
|--------------------------------------------------------------------------
| BODY PARSERS
|--------------------------------------------------------------------------
*/
app.use(express.json({limit:'5mb'}));
app.use(express.urlencoded({extended:true}));

/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/
const SESSION_SECRET=
  process.env.SESSION_SECRET ||
  'change-this-secret-use-a-real-secret-in-production';

app.use(session({
  secret:SESSION_SECRET,
  resave:false,
  saveUninitialized:false,
  proxy:true,
  cookie:{
    httpOnly:true,
    secure:process.env.NODE_ENV==='production',
    sameSite:'lax',
    maxAge:7*24*60*60*1000
  }
}));

/*
|--------------------------------------------------------------------------
| PASSPORT
|--------------------------------------------------------------------------
*/
app.use(passport.initialize());
app.use(passport.session());

/*
|--------------------------------------------------------------------------
| STATIC FILES
|--------------------------------------------------------------------------
*/
app.use('/uploads',express.static(UP));
app.use(express.static(path.join(ROOT,'public')));

/*
|--------------------------------------------------------------------------
| AUTH HELPERS
|--------------------------------------------------------------------------
*/
function auth(req,res,next){
  if(!req.session.userId){
    return res.status(401).json({
      error:'Authentication required'
    });
  }

  const u=read('users').find(
    x=>x.id===req.session.userId
  );

  if(!u||u.active===false){
    req.session.destroy(()=>{});
    return res.status(401).json({
      error:'Account inactive'
    });
  }

  req.user=u;
  next();
}

function role(...roles){
  return (req,res,next)=>{
    if(!roles.includes(req.user.role)){
      return res.status(403).json({
        error:'Permission denied'
      });
    }

    next();
  };
}

function schoolScope(req,obj){
  return (
    req.user.role==='superadmin' ||
    obj.schoolId===req.user.schoolId
  );
}

/*
|--------------------------------------------------------------------------
| UPLOADS
|--------------------------------------------------------------------------
*/
function uploadFor(folder){
  const storage=multer.diskStorage({
    destination:(req,file,cb)=>{
      cb(null,path.join(UP,folder));
    },

    filename:(req,file,cb)=>{
      cb(
        null,
        uid()+path.extname(file.originalname).toLowerCase()
      );
    }
  });

  return multer({
    storage,
    limits:{
      fileSize:5*1024*1024
    },
    fileFilter:(req,file,cb)=>{
      cb(
        null,
        /^image\/(png|jpeg|webp)$/.test(file.mimetype)
      );
    }
  });
}

const profileUpload=uploadFor('profiles');
const logoUpload=uploadFor('schools');

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/
const schoolOf=id=>
  read('schools').find(s=>s.id===id)||null;

const userOf=id=>
  read('users').find(u=>u.id===id)||null;

const subjectOf=id=>
  read('subjects').find(s=>s.id===id)||null;

const examOf=id=>
  read('exams').find(e=>e.id===id)||null;

const questionsOf=id=>
  read('questions').filter(q=>q.examId===id);

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/
app.get('/api/health',(req,res)=>{
  res.json({
    ok:true,
    version:'3.1.0',
    storage:STORAGE_ROOT,
    features:[
      'multi-school',
      'teacher-dashboard',
      'student-dashboard',
      'cbt-arena',
      'results',
      'question-bank',
      'railway-persistent-storage',
      'google-auth'
    ]
  });
});

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/
app.get('/api/me',auth,(req,res)=>{
  res.json({
    user:safe(req.user),
    school:req.user.schoolId
      ?schoolOf(req.user.schoolId)
      :null
  });
});

/*
|--------------------------------------------------------------------------
| REGISTER SCHOOL
|--------------------------------------------------------------------------
*/
app.post('/api/register',async(req,res)=>{
  try{
    const {
      schoolName,
      motto,
      fullName,
      username,
      email,
      password
    }=req.body;

    if(
      !schoolName||
      !fullName||
      !username||
      !email||
      !password
    ){
      return res.status(400).json({
        error:'All required fields must be supplied'
      });
    }

    let users=read('users');

    const normalizedEmail=
      String(email).trim().toLowerCase();

    const normalizedUsername=
      String(username).trim();

    if(
      users.some(u=>
        u.email?.toLowerCase()===normalizedEmail ||
        u.username?.toLowerCase()===normalizedUsername.toLowerCase()
      )
    ){
      return res.status(409).json({
        error:'Username or email already exists'
      });
    }

    let schools=read('schools');

    const school={
      id:uid(),
      name:String(schoolName).trim(),
      motto:String(motto||'').trim(),
      logo:'',
      primaryColor:'#2563eb',
      secondaryColor:'#16a34a',
      theme:'light',
      active:true,
      createdAt:now()
    };

    schools.push(school);
    write('schools',schools);

    const user={
      id:uid(),
      fullName:String(fullName).trim(),
      username:normalizedUsername,
      email:normalizedEmail,
      passwordHash:await bcrypt.hash(password,10),
      role:'school_admin',
      schoolId:school.id,
      active:true,
      provider:'local',
      createdAt:now()
    };

    users.push(user);
    write('users',users);

    req.session.userId=user.id;

    req.session.save(err=>{
      if(err){
        console.error('SESSION SAVE ERROR:',err);
        return res.status(500).json({
          error:'Account created but session could not be started'
        });
      }

      res.json({
        user:safe(user),
        school,
        redirect:'/admin.html'
      });
    });

  }catch(error){
    console.error('REGISTER ERROR:',error);

    res.status(500).json({
      error:'Registration failed'
    });
  }
});

/*
|--------------------------------------------------------------------------
| NORMAL LOGIN
|--------------------------------------------------------------------------
*/
app.post('/api/login',async(req,res)=>{
  try{
    const identifier=
      String(req.body.identifier||'').trim();

    const password=
      String(req.body.password||'');

    if(!identifier||!password){
      return res.status(400).json({
        error:'Username/email and password are required'
      });
    }

    const normalized=
      identifier.toLowerCase();

    const u=read('users').find(x=>
      (
        x.email?.toLowerCase()===normalized ||
        x.username?.toLowerCase()===normalized
      ) &&
      x.active!==false
    );

    if(
      !u ||
      !u.passwordHash ||
      !(await bcrypt.compare(password,u.passwordHash))
    ){
      return res.status(401).json({
        error:'Invalid login details'
      });
    }

    /*
    |--------------------------------------------------------------------------
    | IMPORTANT:
    | Save the session before sending the redirect.
    | This prevents Railway from redirecting back to login
    | before the session is stored.
    |--------------------------------------------------------------------------
    */
    req.session.userId=u.id;

    req.session.save(err=>{
      if(err){
        console.error('LOGIN SESSION SAVE ERROR:',err);

        return res.status(500).json({
          error:'Login successful, but session could not be saved'
        });
      }

      let redirect='/admin.html';

      if(u.role==='student'){
        redirect='/student.html';
      }else if(u.role==='teacher'){
        redirect='/teacher.html';
      }else if(
        u.role==='school_admin'||
        u.role==='superadmin'
      ){
        redirect='/admin.html';
      }

      res.json({
        ok:true,
        user:safe(u),
        redirect
      });
    });

  }catch(error){
    console.error('LOGIN ERROR:',error);

    res.status(500).json({
      error:'An internal error occurred during login'
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/
app.post('/api/logout',(req,res)=>{
  req.session.destroy(err=>{
    if(err){
      return res.status(500).json({
        error:'Logout failed'
      });
    }

    res.clearCookie('connect.sid',{
      httpOnly:true,
      secure:process.env.NODE_ENV==='production',
      sameSite:'lax'
    });

    res.json({
      ok:true
    });
  });
});

/*
|--------------------------------------------------------------------------
| SCHOOL BRANDING
|--------------------------------------------------------------------------
*/
app.put(
  '/api/school/branding',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    const id=
      req.user.role==='superadmin'
        ?req.body.schoolId
        :req.user.schoolId;

    let schools=read('schools');

    const s=schools.find(x=>x.id===id);

    if(!s){
      return res.status(404).json({
        error:'School not found'
      });
    }

    for(
      const k of [
        'name',
        'motto',
        'primaryColor',
        'secondaryColor',
        'theme'
      ]
    ){
      if(req.body[k]!=null){
        s[k]=String(req.body[k]);
      }
    }

    write('schools',schools);

    res.json({
      school:s
    });
  }
);

app.post(
  '/api/school/logo',
  auth,
  role('school_admin','superadmin'),
  logoUpload.single('logo'),
  (req,res)=>{
    const id=
      req.user.role==='superadmin'
        ?req.body.schoolId
        :req.user.schoolId;

    let schools=read('schools');

    const s=schools.find(x=>x.id===id);

    if(!s||!req.file){
      return res.status(400).json({
        error:'School or logo missing'
      });
    }

    s.logo=
      '/uploads/schools/'+req.file.filename;

    write('schools',schools);

    res.json({
      school:s
    });
  }
);

app.post(
  '/api/profile-picture',
  auth,
  profileUpload.single('photo'),
  (req,res)=>{
    if(!req.file){
      return res.status(400).json({
        error:'Image missing'
      });
    }

    let users=read('users');

    const u=users.find(
      x=>x.id===req.user.id
    );

    if(!u){
      return res.status(404).json({
        error:'User not found'
      });
    }

    u.profilePicture=
      '/uploads/profiles/'+req.file.filename;

    write('users',users);

    res.json({
      user:safe(u)
    });
  }
);

app.get('/api/school',auth,(req,res)=>{
  res.json({
    school:schoolOf(req.user.schoolId)
  });
});

/*
|--------------------------------------------------------------------------
| USERS
|--------------------------------------------------------------------------
*/
app.get(
  '/api/users',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    let users=read('users');

    if(req.user.role!=='superadmin'){
      users=users.filter(
        u=>u.schoolId===req.user.schoolId
      );
    }

    res.json(users.map(safe));
  }
);

app.post(
  '/api/users',
  auth,
  role('school_admin','superadmin'),
  async(req,res)=>{
    try{
      const {
        fullName,
        username,
        email,
        password,
        role:ur
      }=req.body;

      if(
        !fullName||
        !username||
        !email||
        !password||
        ![
          'teacher',
          'student',
          'school_admin'
        ].includes(ur)
      ){
        return res.status(400).json({
          error:'Invalid user data'
        });
      }

      let users=read('users');

      const normalizedEmail=
        String(email).trim().toLowerCase();

      const normalizedUsername=
        String(username).trim();

      if(
        users.some(u=>
          u.email?.toLowerCase()===normalizedEmail ||
          u.username?.toLowerCase()===normalizedUsername.toLowerCase()
        )
      ){
        return res.status(409).json({
          error:'User exists'
        });
      }

      const schoolId=
        req.user.role==='superadmin'
          ?req.body.schoolId
          :req.user.schoolId;

      if(!schoolId){
        return res.status(400).json({
          error:'schoolId required'
        });
      }

      if(!schoolOf(schoolId)){
        return res.status(400).json({
          error:'School not found'
        });
      }

      const u={
        id:uid(),
        fullName:String(fullName).trim(),
        username:normalizedUsername,
        email:normalizedEmail,
        passwordHash:await bcrypt.hash(password,10),
        role:ur,
        schoolId,
        active:true,
        provider:'local',
        createdAt:now()
      };

      users.push(u);
      write('users',users);

      res.json({
        user:safe(u)
      });

    }catch(error){
      console.error('CREATE USER ERROR:',error);

      res.status(500).json({
        error:'Could not create user'
      });
    }
  }
);

app.put(
  '/api/users/:id',
  auth,
  role('school_admin','superadmin'),
  async(req,res)=>{
    try{
      let users=read('users');

      const u=users.find(
        x=>x.id===req.params.id
      );

      if(!u||!schoolScope(req,u)){
        return res.status(404).json({
          error:'User not found'
        });
      }

      for(
        const k of [
          'fullName',
          'username',
          'email',
          'active'
        ]
      ){
        if(req.body[k]!=null){
          u[k]=req.body[k];
        }
      }

      if(
        req.body.role &&
        [
          'teacher',
          'student',
          'school_admin'
        ].includes(req.body.role)
      ){
        u.role=req.body.role;
      }

      if(req.body.password){
        u.passwordHash=
          await bcrypt.hash(
            req.body.password,
            10
          );
      }

      write('users',users);

      res.json({
        user:safe(u)
      });

    }catch(error){
      console.error('UPDATE USER ERROR:',error);

      res.status(500).json({
        error:'Could not update user'
      });
    }
  }
);

app.delete(
  '/api/users/:id',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    let users=read('users');

    const u=users.find(
      x=>x.id===req.params.id
    );

    if(!u||!schoolScope(req,u)){
      return res.status(404).json({
        error:'User not found'
      });
    }

    users=users.filter(
      x=>x.id!==u.id
    );

    write('users',users);

    res.json({
      ok:true
    });
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN SUMMARY
|--------------------------------------------------------------------------
*/
app.get(
  '/api/admin/summary',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    const us=
      req.user.role==='superadmin'
        ?read('users')
        :read('users').filter(
          u=>u.schoolId===req.user.schoolId
        );

    const ss=
      req.user.role==='superadmin'
        ?read('schools')
        :read('schools').filter(
          s=>s.id===req.user.schoolId
        );

    res.json({
      students:us.filter(
        u=>u.role==='student'
      ).length,

      teachers:us.filter(
        u=>u.role==='teacher'
      ).length,

      admins:us.filter(
        u=>u.role==='school_admin'
      ).length,

      schools:ss.length,

      subjects:read('subjects').filter(
        x=>
          req.user.role==='superadmin' ||
          x.schoolId===req.user.schoolId
      ).length,

      exams:read('exams').filter(
        x=>
          req.user.role==='superadmin' ||
          x.schoolId===req.user.schoolId
      ).length,

      results:read('results').filter(
        x=>
          req.user.role==='superadmin' ||
          x.schoolId===req.user.schoolId
      ).length
    });
  }
);

/*
|--------------------------------------------------------------------------
| TEACHER SUMMARY
|--------------------------------------------------------------------------
*/
app.get(
  '/api/teacher/summary',
  auth,
  role('teacher','school_admin','superadmin'),
  (req,res)=>{
    let exams;
    let results;
    let students;
    let subjects;

    if(req.user.role==='superadmin'){
      exams=read('exams');
      results=read('results');
      students=read('users').filter(
        u=>u.role==='student'
      );
      subjects=read('subjects');
    }else{
      const sid=req.user.schoolId;

      exams=read('exams').filter(
        e=>e.schoolId===sid
      );

      results=read('results').filter(
        r=>r.schoolId===sid
      );

      students=read('users').filter(
        u=>
          u.schoolId===sid &&
          u.role==='student'
      );

      subjects=read('subjects').filter(
        s=>s.schoolId===sid
      );
    }

    const published=
      exams.filter(
        e=>e.status==='published'
      );

    const avg=
      results.length
        ?Math.round(
          results.reduce(
            (n,r)=>
              n+Number(r.percentage||0),
            0
          )/results.length*10
        )/10
        :0;

    res.json({
      subjects:subjects.length,
      exams:exams.length,
      published:published.length,
      students:students.length,
      submissions:results.length,
      average:avg,
      questions:read('questions').filter(
        q=>exams.some(e=>e.id===q.examId)
      ).length
    });
  }
);

/*
|--------------------------------------------------------------------------
| STUDENT SUMMARY
|--------------------------------------------------------------------------
*/
app.get(
  '/api/student/summary',
  auth,
  role('student'),
  (req,res)=>{
    const exams=read('exams').filter(
      e=>
        e.schoolId===req.user.schoolId &&
        e.status==='published'
    );

    const results=read('results').filter(
      r=>
        r.schoolId===req.user.schoolId &&
        r.studentId===req.user.id
    );

    const done=new Set(
      results.map(r=>r.examId)
    );

    const avg=
      results.length
        ?Math.round(
          results.reduce(
            (n,r)=>
              n+Number(r.percentage||0),
            0
          )/results.length*10
        )/10
        :0;

    res.json({
      available:exams.filter(
        e=>!done.has(e.id)
      ).length,
      completed:results.length,
      average:avg,
      totalExams:exams.length
    });
  }
);

/*
|--------------------------------------------------------------------------
| SUBJECTS
|--------------------------------------------------------------------------
*/
app.get('/api/subjects',auth,(req,res)=>{
  res.json(
    read('subjects').filter(
      x=>schoolScope(req,x)
    )
  );
});

app.post(
  '/api/subjects',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    const schoolId=
      req.user.role==='superadmin'
        ?req.body.schoolId
        :req.user.schoolId;

    if(!schoolId||!req.body.name){
      return res.status(400).json({
        error:'Name and school required'
      });
    }

    let a=read('subjects');

    const x={
      id:uid(),
      schoolId,
      name:req.body.name,
      code:req.body.code||'',
      description:req.body.description||'',
      createdBy:req.user.id,
      createdAt:now()
    };

    a.push(x);
    write('subjects',a);

    res.json({
      subject:x
    });
  }
);

app.put(
  '/api/subjects/:id',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    let a=read('subjects');

    const x=a.find(
      v=>v.id===req.params.id
    );

    if(!x||!schoolScope(req,x)){
      return res.status(404).json({
        error:'Subject not found'
      });
    }

    Object.assign(x,{
      name:req.body.name??x.name,
      code:req.body.code??x.code,
      description:req.body.description??x.description
    });

    write('subjects',a);

    res.json({
      subject:x
    });
  }
);

app.delete(
  '/api/subjects/:id',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    let a=read('subjects');

    const x=a.find(
      v=>v.id===req.params.id
    );

    if(!x||!schoolScope(req,x)){
      return res.status(404).json({
        error:'Subject not found'
      });
    }

    write(
      'subjects',
      a.filter(v=>v.id!==x.id)
    );

    res.json({
      ok:true
    });
  }
);

/*
|--------------------------------------------------------------------------
| ANNOUNCEMENTS
|--------------------------------------------------------------------------
*/
app.get(
  '/api/announcements',
  auth,
  (req,res)=>{
    res.json(
      read('announcements')
        .filter(x=>schoolScope(req,x))
        .sort(
          (a,b)=>
            b.createdAt.localeCompare(a.createdAt)
        )
    );
  }
);

app.post(
  '/api/announcements',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    const schoolId=
      req.user.role==='superadmin'
        ?req.body.schoolId
        :req.user.schoolId;

    const x={
      id:uid(),
      schoolId,
      title:req.body.title,
      body:req.body.body,
      createdBy:req.user.id,
      createdAt:now()
    };

    if(!x.title||!x.body){
      return res.status(400).json({
        error:'Title and body required'
      });
    }

    let a=read('announcements');

    a.push(x);
    write('announcements',a);

    res.json({
      announcement:x
    });
  }
);

app.delete(
  '/api/announcements/:id',
  auth,
  role('school_admin','superadmin'),
  (req,res)=>{
    let a=read('announcements');

    const x=a.find(
      v=>v.id===req.params.id
    );

    if(!x||!schoolScope(req,x)){
      return res.status(404).json({
        error:'Not found'
      });
    }

    write(
      'announcements',
      a.filter(v=>v.id!==x.id)
    );

    res.json({
      ok:true
    });
  }
);

/*
|--------------------------------------------------------------------------
| CBT / EXAMS
|--------------------------------------------------------------------------
*/
app.get('/api/exams',auth,(req,res)=>{
  const exams=read('exams')
    .filter(x=>schoolScope(req,x));

  const results=read('results');

  res.json(
    exams.map(e=>({
      ...e,
      subject:
        subjectOf(e.subjectId)?.name ||
        'Unknown subject',

      questionCount:
        questionsOf(e.id).length,

      submissionCount:
        results.filter(
          r=>r.examId===e.id
        ).length
    }))
  );
});

app.get(
  '/api/exams/:id',
  auth,
  (req,res)=>{
    const e=examOf(req.params.id);

    if(!e||!schoolScope(req,e)){
      return res.status(404).json({
        error:'Exam not found'
      });
    }

    res.json({
      ...e,
      subject:subjectOf(e.subjectId),
      questionCount:
        questionsOf(e.id).length,
      submissionCount:
        read('results').filter(
          r=>r.examId===e.id
        ).length
    });
  }
);

app.post(
  '/api/exams',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    const schoolId=
      req.user.role==='superadmin'
        ?req.body.schoolId
        :req.user.schoolId;

    const subject=
      read('subjects').find(
        s=>
          s.id===req.body.subjectId &&
          s.schoolId===schoolId
      );

    if(!subject){
      return res.status(400).json({
        error:'Invalid subject'
      });
    }

    const e={
      id:uid(),
      schoolId,
      subjectId:subject.id,
      title:String(
        req.body.title||'Untitled CBT'
      ).trim(),
      duration:Number(req.body.duration)||30,
      instructions:req.body.instructions||'',
      status:
        req.body.status==='published'
          ?'published'
          :'draft',
      createdBy:req.user.id,
      createdAt:now()
    };

    if(!e.title){
      return res.status(400).json({
        error:'Exam title required'
      });
    }

    let a=read('exams');

    a.push(e);
    write('exams',a);

    res.json({
      exam:e
    });
  }
);

app.put(
  '/api/exams/:id',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    let a=read('exams');

    const e=a.find(
      x=>x.id===req.params.id
    );

    if(!e||!schoolScope(req,e)){
      return res.status(404).json({
        error:'Exam not found'
      });
    }

    for(
      const k of [
        'title',
        'instructions',
        'status'
      ]
    ){
      if(req.body[k]!=null){
        e[k]=req.body[k];
      }
    }

    if(req.body.duration!=null){
      e.duration=
        Math.max(
          1,
          Number(req.body.duration)||30
        );
    }

    write('exams',a);

    res.json({
      exam:e
    });
  }
);

app.delete(
  '/api/exams/:id',
  auth,
  role('school_admin','teacher','superadmin'),
  (req,res)=>{
    let a=read('exams');

    const e=a.find(
      x=>x.id===req.params.id
    );

    if(!e||!schoolScope(req,e)){
      return res.status(404).json({
        error:'Exam not found'
      });
    }

    write(
      'exams',
      a.filter(x=>x.id!==e.id)
    );

    write(
      'questions',
      read('questions').filter(
        q=>q.examId!==e.id
      )
    );

    write(
      'results',
      read('results').filter(
        r=>r.examId!==e.id
      )
    );

    res.json({
      ok:true
    });
  }
);

/*
|--------------------------------------------------------------------------
| QUESTION HELPERS
|--------------------------------------------------------------------------
*/
