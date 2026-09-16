const $=s=>document.querySelector(s);const $$=s=>document.querySelectorAll(s);let ME=null;
async function api(url,opt={}){const r=await fetch(url,{credentials:'include',headers:{'Content-Type':'application/json',...(opt.headers||{})},...opt});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Request failed');return d}
function toast(x){const t=$('#toast');if(!t)return;t.textContent=x;t.style.display='block';setTimeout(()=>t.style.display='none',2500)}
async function boot(){try{const d=await api('/api/me');ME=d.user;window.SCHOOL=d.school;applyBrand(d.school);if($('#meName'))$('#meName').textContent=ME.fullName;if($('#meRole'))$('#meRole').textContent=ME.role.replace('_',' ');if($('#mePic')&&ME.profilePicture)$('#mePic').src=ME.profilePicture;return true}catch{return false}}
function applyBrand(s){if(!s)return;document.documentElement.style.setProperty('--primary',s.primaryColor||'#2563eb');document.documentElement.style.setProperty('--secondary',s.secondaryColor||'#16a34a');document.querySelectorAll('[data-school-name]').forEach(x=>x.textContent=s.name);document.querySelectorAll('[data-school-motto]').forEach(x=>x.textContent=s.motto||'Smart school management');document.querySelectorAll('[data-logo]').forEach(x=>{if(s.logo){x.src=s.logo;x.style.display='block'}});if(s.theme==='dark')document.body.style.background='#0f172a'}
async function logout(){await api('/api/logout',{method:'POST'});location='/login.html'}
function nav(){ $$('.nav button').forEach(b=>b.onclick=()=>{$$('.section').forEach(s=>s.classList.remove('show'));$('#'+b.dataset.section).classList.add('show');$$('.nav button').forEach(x=>x.classList.remove('active'));b.classList.add('active')})}

// Responsive motion layer: lightweight reveal animations, button ripples and page entrance.
document.addEventListener('DOMContentLoaded',()=>{
  document.body.classList.add('page-ready');
  document.querySelectorAll('.card,.feature,.authbox,.hero .container > div').forEach(el=>{
    if(!el.closest('.mock') && !el.classList.contains('authbox')) el.classList.add('reveal');
  });
  const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const reveal=()=>document.querySelectorAll('.reveal').forEach(el=>{
    const r=el.getBoundingClientRect();
    if(r.top<window.innerHeight*.92) el.classList.add('visible');
  });
  if(!reduced && 'IntersectionObserver' in window){
    const io=new IntersectionObserver(entries=>entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');io.unobserve(e.target)}}),{threshold:.08});
    document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
  }else reveal();
  window.addEventListener('scroll',()=>{if(!reduced) reveal()},{passive:true});
  document.querySelectorAll('.btn').forEach(btn=>btn.addEventListener('click',e=>{
    if(reduced)return;
    const s=document.createElement('span');s.style.cssText='position:absolute;border-radius:50%;pointer-events:none;width:20px;height:20px;background:rgba(255,255,255,.35);transform:scale(0);animation:ripple .55s ease-out';
    const rect=btn.getBoundingClientRect();s.style.left=(e.clientX-rect.left-10)+'px';s.style.top=(e.clientY-rect.top-10)+'px';
    if(getComputedStyle(btn).position==='static')btn.style.position='relative';btn.style.overflow='hidden';btn.appendChild(s);setTimeout(()=>s.remove(),600);
  }));
  if(!document.getElementById('motion-style')){const st=document.createElement('style');st.id='motion-style';st.textContent='@keyframes ripple{to{transform:scale(14);opacity:0}}';document.head.appendChild(st)}
});
