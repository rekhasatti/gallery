'use strict';
// DB "MyGalleryDB" v1. media: normal photos/videos/notes {id,kind,name,type,blob|text,title,created}
// vault: {id,iv,data,v:1}; data = AES-GCM(pack(header JSON, payload bytes)). meta: {k:'vault',salt,it,iv,data}
const $=s=>document.querySelector(s),TE=new TextEncoder,TD=new TextDecoder;
const DB_NAME='MyGalleryDB',DB_VER=1,PBKDF2_IT=310000;
const lockMs=()=>(+localStorage.getItem('lockMin')||2)*60000;
let sel=new Set(),selMode=false,bulkBusy=false,bioRec=null;
let db,key=null,view='all',items=[],urls=[],busy=new Set(),lockT,q='',picking=false;
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
const msg=e=>e&&e.name==='QuotaExceededError'?'Storage is full':(e&&e.message||String(e));
function toast(m,bad){const t=$('#toast');t.textContent=m;t.className='show'+(bad?' bad':'');clearTimeout(toast.t);toast.t=setTimeout(()=>t.className='',3500)}
function openDB(){return new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,DB_VER);r.onupgradeneeded=()=>{const d=r.result;
 [['media','id'],['vault','id'],['meta','k']].forEach(([s,k])=>{if(!d.objectStoreNames.contains(s))d.createObjectStore(s,{keyPath:k})})};
 r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)})}
const rq=(s,m,f)=>new Promise((res,rej)=>{const t=db.transaction(s,m),r=f(t.objectStore(s));t.oncomplete=()=>res(r&&r.result);t.onerror=t.onabort=()=>rej(t.error||new Error('Database error'))});
const get=(s,k)=>rq(s,'readonly',o=>o.get(k)),put=(s,v)=>rq(s,'readwrite',o=>o.put(v)),del=(s,k)=>rq(s,'readwrite',o=>o.delete(k)),all=s=>rq(s,'readonly',o=>o.getAll());
// crypto
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
async function derive(pw,salt,it,ex=false){const m=await crypto.subtle.importKey('raw',TE.encode(pw),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:it,hash:'SHA-256'},m,{name:'AES-GCM',length:256},ex,['encrypt','decrypt'])}
async function enc(buf){const iv=rnd(12);return{iv,data:await crypto.subtle.encrypt({name:'AES-GCM',iv},key,buf)}}
const dec=r=>crypto.subtle.decrypt({name:'AES-GCM',iv:r.iv},key,r.data);
function pack(h,p){const hb=TE.encode(JSON.stringify(h)),o=new Uint8Array(4+hb.length+p.byteLength);new DataView(o.buffer).setUint32(0,hb.length);o.set(hb,4);o.set(new Uint8Array(p),4+hb.length);return o.buffer}
function unpack(b){const n=new DataView(b).getUint32(0);return{h:JSON.parse(TD.decode(new Uint8Array(b,4,n))),p:b.slice(4+n)}}
const same=(a,b)=>{if(a.byteLength!==b.byteLength)return false;const x=new Uint8Array(a),y=new Uint8Array(b);for(let i=0;i<x.length;i++)if(x[i]!==y[i])return false;return true};
async function privItem(r){const{h,p}=unpack(await dec(r));const it={...h,id:r.id,priv:true};if(h.kind==='note')it.text=TD.decode(p);else it.blob=new Blob([p],{type:h.type});return it}
const payloadOf=async i=>i.kind==='note'?TE.encode(i.text||'').buffer:await i.blob.arrayBuffer();
const headerOf=i=>({kind:i.kind,name:i.name,type:i.type,title:i.title,created:i.created});
// vault auth
function askPw(setup,title){return new Promise(res=>{const d=$('#pwDlg');$('#pwT').textContent=setup?'Create vault password':(title||'Unlock vault');
 $('#pwNote').textContent=setup?'Minimum 8 characters. If you forget it, private items cannot be recovered.':'Enter your vault password.';
 $('#pw2').hidden=!setup;const bb=$('#pwBio');bb.hidden=!(bioRec&&hasBioApi()&&!setup&&!title);
 bb.onclick=async()=>{try{const k=await bioKey(bioRec);if(k)fin({key:k})}catch(e){$('#pwErr').textContent='Biometric failed ('+msg(e)+'). Use your passcode.'}};$('#pw').value=$('#pw2').value='';$('#pwErr').textContent='';let done=false;
 const fin=v=>{if(done)return;done=true;d.close();res(v)};
 $('#pwOk').onclick=()=>{const p=$('#pw').value;if(!p)return;if(setup&&p.length<8){$('#pwErr').textContent='Use at least 8 characters';return}
  if(setup&&p!==$('#pw2').value){$('#pwErr').textContent='Passwords do not match';return}fin(p)};
 [$('#pw'),$('#pw2')].forEach(i=>i.onkeydown=e=>{if(e.key==='Enter')$('#pwOk').click()});
 $('#pwCancel').onclick=()=>fin(null);d.oncancel=e=>{e.preventDefault();fin(null)};d.showModal();$('#pw').focus()})}
async function needVault(){if(key)return true;const m=await get('meta','vault');const pw=await askPw(!m);if(pw==null)return false;if(typeof pw==='object'){key=pw.key;resetLock();await refresh();return true}
 try{if(!m){const salt=rnd(16);key=await derive(pw,salt,PBKDF2_IT);const c=await enc(TE.encode('MYGALLERY-OK'));await put('meta',{k:'vault',salt,it:PBKDF2_IT,iv:c.iv,data:c.data})}
 else{const k=await derive(pw,m.salt,m.it);try{await crypto.subtle.decrypt({name:'AES-GCM',iv:m.iv},k,m.data)}catch{toast('Wrong password',1);return false}key=k}
 resetLock();await refresh();return true}catch(e){key=null;toast('Vault error: '+msg(e),1);return false}}
function lock(){if(!key)return;key=null;items=items.filter(i=>!i.priv);render()}
function resetLock(){clearTimeout(lockT);if(key)lockT=setTimeout(lock,lockMs())}
['pointerdown','keydown','scroll'].forEach(e=>addEventListener(e,resetLock,{passive:true}));
document.addEventListener('visibilitychange',()=>{if(document.hidden&&!picking&&!bulkBusy)lock()});
addEventListener('pagehide',lock);
// data
async function refresh(){items=(await all('media')).map(r=>({...r,priv:false}));
 if(key)for(const r of await all('vault')){try{items.push(await privItem(r))}catch(e){console.warn('skip',r.id,e)}}render()}
const inView=i=>view==='vault'?i.priv:view==='notes'?!i.priv&&i.kind==='note':view==='normal'?!i.priv&&i.kind!=='note':!i.priv;
function render(){urls.forEach(URL.revokeObjectURL);urls=[];const g=$('#grid');g.replaceChildren();
 $('#title').textContent=({all:'My Gallery',normal:'Normal Gallery',vault:'Private Vault',notes:'Text Notes'})[view]||'My Gallery';
 document.querySelectorAll('#nav button').forEach(b=>b.classList.toggle('on',b.dataset.v===view));
 const locked=view==='vault'&&!key;let list=locked?[]:items.filter(inView);
 if(q)list=list.filter(i=>((i.name||'')+' '+(i.title||'')+' '+(i.text||'')).toLowerCase().includes(q));
 list.sort((a,b)=>b.created-a.created).forEach(i=>g.append(tile(i)));
 $('#empty').hidden=list.length>0;$('#unlockBtn').hidden=!locked;$('#emptyT').textContent=locked?'Vault is locked':q?'No matches':'Nothing here yet';updSel()}
function tile(it){const t=el('div','tile');t.tabIndex=0;t.dataset.id=it.id;t.setAttribute('aria-label',it.title||it.name||'item');
 if(it.kind==='note'){t.classList.add('note');t.append(el('b','',it.title||'Untitled'),el('p','',(it.text||'').slice(0,160)))}
 else{const u=URL.createObjectURL(it.blob);urls.push(u);
  if(it.kind==='video'){const v=document.createElement('video');v.src=u+'#t=0.1';v.muted=true;v.preload='metadata';v.playsInline=true;t.append(v,el('span','badge','▶'))}
  else{const i=new Image();i.src=u;i.alt=it.name||'';i.loading='lazy';t.append(i)}}
 const m=el('button','dots','⋮');m.setAttribute('aria-label','Item menu');m.onclick=e=>{e.stopPropagation();const r=m.getBoundingClientRect();menu(it,r.left,r.bottom)};t.append(m);
 const ck=el('button','chk','✓');ck.setAttribute('aria-label','Select');ck.onclick=e=>{e.stopPropagation();toggle(it.id)};t.append(ck);t.classList.toggle('sel',sel.has(it.id));
 let tm,fired=false;t.onclick=e=>{if(fired){fired=false;return}if(selMode||e.ctrlKey||e.metaKey||e.shiftKey)toggle(it.id);else openItem(it)};
 t.onkeydown=e=>{if(e.key===' '){e.preventDefault();toggle(it.id)}if(e.key==='Enter')selMode?toggle(it.id):openItem(it);if(e.key==='ContextMenu'||(e.shiftKey&&e.key==='F10')){e.preventDefault();const r=t.getBoundingClientRect();menu(it,r.left+10,r.top+10)}};
 t.oncontextmenu=e=>{e.preventDefault();if(fired||e.pointerType==='touch')return;menu(it,e.clientX,e.clientY)};
 t.addEventListener('touchstart',()=>{fired=false;tm=setTimeout(()=>{fired=true;selMode?toggle(it.id):startSel(it.id);if(navigator.vibrate)navigator.vibrate(20)},450)},{passive:true});
 ['touchend','touchmove','touchcancel'].forEach(n=>t.addEventListener(n,()=>clearTimeout(tm),{passive:true}));return t}
// context menu
function menu(it,x,y){closeMenus();const c=$('#ctx'),n=it.kind==='note';
 const A=[[n?'Open / Edit':'Open / View',()=>openItem(it)],['Select',()=>startSel(it.id)]];if(n)A.push(['Copy',()=>copy(it)]);
 A.push(['Share',()=>share(it)],[n?'Download as TXT':'Download',()=>download(it)],
  [it.priv?'Move to Normal Gallery':'Move to Private Album',()=>it.priv?toNormal(it):toPrivate(it)],['Delete',()=>remove(it),1]);
 c.replaceChildren();A.forEach(([l,f,d])=>{const b=el('button',d?'danger':'',l);b.setAttribute('role','menuitem');b.onclick=()=>{closeMenus();f()};c.append(b)});
 c.hidden=false;c.style.left=Math.max(4,Math.min(x,innerWidth-c.offsetWidth-4))+'px';c.style.top=Math.max(4,Math.min(y,innerHeight-c.offsetHeight-4))+'px';c.firstChild.focus()}
function closeMenus(){$('#ctx').hidden=true;$('#fabMenu').hidden=true;$('#nav').hidden=true}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeMenus();
 if(!$('#ctx').hidden&&(e.key==='ArrowDown'||e.key==='ArrowUp')){e.preventDefault();const b=[...$('#ctx').children],i=b.indexOf(document.activeElement);b[(i+(e.key==='ArrowDown'?1:-1)+b.length)%b.length].focus()}});
document.addEventListener('pointerdown',e=>{if(!e.target.closest('#ctx,#fabMenu,#fab,#nav,#menuBtn,#title,.dots'))closeMenus()});
addEventListener('resize',closeMenus);
// actions
function openItem(it){if(it.kind==='note')return noteEdit(it);const b=$('#vBody');b.replaceChildren();const u=URL.createObjectURL(it.blob);
 let m;if(it.kind==='video'){m=document.createElement('video');m.controls=true;m.autoplay=true;m.playsInline=true}else{m=new Image();m.alt=it.name||''}m.src=u;b.append(m);
 const v=$('#viewer');v.onclose=()=>{b.replaceChildren();URL.revokeObjectURL(u)};v.showModal()}
$('#vClose').onclick=()=>$('#viewer').close();
const fname=i=>(i.kind==='note'?(i.title||'note')+'.txt':i.name||'file').replace(/[\\/:*?"<>|]/g,'_');
function download(it){const b=it.kind==='note'?new Blob([(it.title?it.title+'\n\n':'')+it.text],{type:'text/plain;charset=utf-8'}):it.blob;
 const u=URL.createObjectURL(b),a=el('a');a.href=u;a.download=fname(it);document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),4000)}
async function copy(it){try{await navigator.clipboard.writeText(it.text);toast('Copied')}catch(e){toast('Copy failed: '+msg(e),1)}}
async function share(it){try{if(it.kind==='note'){if(navigator.share)await navigator.share({title:it.title,text:it.text});else{await copy(it)}return}
 const f=new File([it.blob],fname(it),{type:it.type});if(navigator.canShare&&navigator.canShare({files:[f]}))await navigator.share({files:[f]});else{download(it);toast('Sharing not supported here; downloaded instead')}}
 catch(e){if(e.name!=='AbortError')toast('Share failed: '+msg(e),1)}}
async function remove(it){if(!confirm('Delete this imported copy'+(it.priv?' from the Private Vault':'')+'? Original files in your phone gallery are not touched.'))return;
 try{await del(it.priv?'vault':'media',it.id);toast('Deleted');await refresh()}catch(e){toast('Delete failed: '+msg(e),1)}}
const label=i=>i.title||i.name||'item';
// Move core: write -> read back & verify -> only then delete source. Throws on any failure (source is kept).
async function mvPriv(it){if(!key)throw Error('Vault is locked');const rec=await get('media',it.id);if(!rec)throw Error('Item no longer exists');
 const p=await payloadOf(rec),dup=items.find(x=>x.priv&&x.oid===rec.id);
 if(dup&&same(await payloadOf(dup),p)){await del('media',rec.id);return}  // leftover of an interrupted move: private copy already verified identical
 const h={...headerOf(rec),oid:rec.id},nid=crypto.randomUUID();
 try{const e=await enc(pack(h,p));await put('vault',{id:nid,iv:e.iv,data:e.data,v:1});const back=await get('vault',nid);if(!back)throw Error('Read-back failed');
  const c=unpack(await dec(back));if(c.h.created!==h.created||!same(c.p,p))throw Error('Verification failed')}
 catch(e){try{await del('vault',nid)}catch{}throw e}
 await del('media',rec.id)}
async function mvNormal(it){if(!key)throw Error('Vault is locked');const r=await get('vault',it.id);if(!r)throw Error('Item no longer exists');const x=await privItem(r),xp=await payloadOf(x);
 const dup=items.find(i=>!i.priv&&i.oid===x.id);if(dup&&same(await payloadOf(dup),xp)){await del('vault',r.id);return}
 const rec={id:crypto.randomUUID(),kind:x.kind,name:x.name,type:x.type,title:x.title,created:x.created,oid:x.id};if(x.kind==='note')rec.text=x.text;else rec.blob=x.blob;
 try{await put('media',rec);const back=await get('media',rec.id);if(!back||!same(await payloadOf(back),xp))throw Error('Verification failed')}
 catch(e){try{await del('media',rec.id)}catch{}throw e}
 await del('vault',r.id)}
async function moveOne(it,toPriv){if(bulkBusy||busy.has(it.id))return;busy.add(it.id);
 try{if(!await needVault())return;await(toPriv?mvPriv(it):mvNormal(it));toast(toPriv?'Moved to Private Vault':'Moved to Normal Gallery')}
 catch(e){toast('Move failed, original kept: '+msg(e),1)}finally{busy.delete(it.id);await refresh()}}
const toPrivate=it=>moveOne(it,true),toNormal=it=>moveOne(it,false);
// import
async function addFiles(files){const priv=view==='vault';if(priv&&!await needVault())return;let ok=0,fail=0,last='';
 for(const f of files){if(!/^(image|video)\//.test(f.type)){fail++;continue}
  const rec={id:crypto.randomUUID(),kind:f.type.startsWith('video')?'video':'photo',name:f.name,type:f.type,title:'',created:Date.now()+ok};
  try{if(priv){const e=await enc(pack(headerOf(rec),await f.arrayBuffer()));await put('vault',{id:rec.id,iv:e.iv,data:e.data,v:1})}else{rec.blob=f;await put('media',rec)}ok++}
  catch(e){fail++;last=msg(e)}}
 toast(`Imported ${ok}`+(fail?`, ${fail} failed${last?' ('+last+')':''}`:''),fail&&!ok);await refresh()}
[['fp'],['fv']].forEach(([id])=>{const i=$('#'+id);i.onclick=()=>picking=true;i.oncancel=()=>picking=false;i.onchange=async()=>{const f=[...i.files];i.value='';picking=false;if(f.length)await addFiles(f)}});
// notes
let editing=null;
function noteEdit(it){editing=it||null;$('#nTitle').value=it?it.title||'':'';$('#nText').value=it?it.text||'':'';$('#nDestL').hidden=!!it;$('#nDest').value=view==='vault'?'p':'n';$('#noteDlg').showModal()}
$('#nCancel').onclick=()=>$('#noteDlg').close();
$('#nSave').onclick=async()=>{const title=$('#nTitle').value.trim(),text=$('#nText').value;if(!title&&!text.trim()){toast('Note is empty',1);return}
 const priv=editing?editing.priv:$('#nDest').value==='p';if(priv&&!await needVault())return;
 const rec={id:editing?editing.id:crypto.randomUUID(),kind:'note',name:'',type:'text/plain',title,text,created:editing?editing.created:Date.now()};
 try{if(priv){const e=await enc(pack(headerOf(rec),TE.encode(text).buffer));await put('vault',{id:rec.id,iv:e.iv,data:e.data,v:1})}else await put('media',rec);
  $('#noteDlg').close();toast('Note saved');await refresh()}catch(e){toast('Save failed: '+msg(e),1)}};
// UI wiring
$('#fab').onclick=()=>{const m=$('#fabMenu');const o=m.hidden;closeMenus();m.hidden=!o};
$('#fabMenu').onclick=e=>{const a=e.target.dataset.a;if(!a)return;closeMenus();if(a==='photo')$('#fp').click();else if(a==='video')$('#fv').click();else noteEdit()};
const navT=()=>{const n=$('#nav');const o=n.hidden;closeMenus();n.hidden=!o};$('#menuBtn').onclick=navT;$('#title').onclick=navT;
$('#nav').onclick=e=>{const v=e.target.dataset.v;if(!v)return;closeMenus();if(v==='settings')return openSettings();view=v;sel.clear();selMode=false;render()};
$('#searchBtn').onclick=()=>{const s=$('#q');s.hidden=!s.hidden;if(s.hidden){s.value='';q='';render()}else s.focus()};
$('#q').oninput=e=>{q=e.target.value.trim().toLowerCase();render()};
$('#unlockBtn').onclick=()=>needVault();
async function openSettings(){$('#store').textContent='';$('#lockMin').value=String(+localStorage.getItem('lockMin')||2);refreshAuth();try{const s=await navigator.storage.estimate();$('#store').textContent=`Storage used: ${(s.usage/1048576).toFixed(1)} MB of about ${(s.quota/1048576).toFixed(0)} MB`}catch{}$('#setDlg').showModal()}
$('#setBtn').onclick=openSettings;$('#setClose').onclick=()=>$('#setDlg').close();
$('#lockNow').onclick=()=>{lock();toast('Vault locked')};
$('#persist').onclick=async()=>{try{toast(await navigator.storage.persist()?'Storage protected from automatic clearing':'Browser declined; keep backups of important files')}catch{toast('Not supported',1)}};
// ---- multi-select & bulk actions ----
const selList=()=>items.filter(i=>sel.has(i.id));
function updSel(){for(const id of [...sel])if(!items.some(i=>i.id===id&&inView(i)))sel.delete(id);selMode=sel.size>0;
 document.body.classList.toggle('sel',selMode);$('#selBar').hidden=!selMode;$('#selN').textContent=sel.size+' selected';
 $('#selMove').textContent=view==='vault'?'Move to Normal':'Move to Private';
 document.querySelectorAll('.tile').forEach(t=>{const on=sel.has(t.dataset.id);t.classList.toggle('sel',on);t.setAttribute('aria-selected',on)})}
const toggle=id=>{sel.has(id)?sel.delete(id):sel.add(id);updSel()},startSel=id=>{sel.add(id);updSel()};
$('#selX').onclick=()=>{sel.clear();updSel()};
$('#selAll').onclick=()=>{const t=[...document.querySelectorAll('.tile')],all=t.every(x=>sel.has(x.dataset.id));t.forEach(x=>all?sel.delete(x.dataset.id):sel.add(x.dataset.id));updSel()};
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&selMode&&$('#ctx').hidden){sel.clear();updSel()}});
function prog(t){const d=$('#prog');$('#progT').textContent=t;$('#progMsg').textContent='';$('#pbar').max=1;$('#pbar').value=0;$('#progOk').hidden=true;d.oncancel=e=>e.preventDefault();d.showModal();
 return{set:(i,n,m)=>{$('#pbar').max=n;$('#pbar').value=i;$('#progMsg').textContent=m},done:m=>{$('#pbar').value=$('#pbar').max;$('#progMsg').textContent=m;$('#progOk').hidden=false;$('#progOk').onclick=()=>d.close()}}}
$('#selMove').onclick=async()=>{const toPriv=view!=='vault',list=selList();if(bulkBusy||!list.length)return;if(!await needVault())return;
 bulkBusy=true;const p=prog(toPriv?'Moving to Private Vault':'Moving to Normal Gallery');let ok=0;const bad=[];
 for(let i=0;i<list.length;i++){const it=list[i];resetLock();p.set(i,list.length,`${i+1} of ${list.length}: ${label(it)}`);
  if(busy.has(it.id)){bad.push(label(it)+': already being moved');continue}busy.add(it.id);
  try{await(toPriv?mvPriv(it):mvNormal(it));ok++}catch(e){bad.push(label(it)+': '+msg(e))}finally{busy.delete(it.id)}}
 bulkBusy=false;sel.clear();await refresh();
 p.done(`${ok} of ${list.length} moved.`+(bad.length?`\n${bad.length} failed and stayed where they were:\n`+bad.join('\n'):' All verified.'));if(document.hidden)lock()};
$('#selDel').onclick=async()=>{const list=selList();if(!list.length||bulkBusy)return;
 if(!confirm(`Delete ${list.length} imported cop${list.length>1?'ies':'y'}? Original files in your phone gallery are not touched.`))return;
 let ok=0,bad=0;for(const it of list){try{await del(it.priv?'vault':'media',it.id);ok++}catch{bad++}}
 sel.clear();await refresh();toast(`Deleted ${ok}`+(bad?`, ${bad} failed`:''),bad>0)};
$('#selShare').onclick=async()=>{const files=selList().map(i=>i.kind==='note'?new File([(i.title?i.title+'\n\n':'')+i.text],fname(i),{type:'text/plain'}):new File([i.blob],fname(i),{type:i.type}));
 try{if(navigator.canShare&&navigator.canShare({files}))await navigator.share({files});else toast('This browser cannot share these files together. Use Download.',1)}
 catch(e){if(e.name!=='AbortError')toast('Share failed: '+msg(e),1)}};
$('#selDl').onclick=async()=>{for(const it of selList()){download(it);await new Promise(r=>setTimeout(r,400))}toast('Downloads started (Chrome may ask to allow multiple downloads)')};
// ---- biometric (WebAuthn PRF) & passcode management ----
// The vault key is never stored. Enabling biometrics wraps the (passcode-derived) vault key with a key derived from the
// authenticator's PRF secret, which the device only releases after user verification (fingerprint, face or screen lock).
const hasBioApi=()=>!!(window.PublicKeyCredential&&navigator.credentials);
async function bioAvail(){try{return hasBioApi()&&await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()}catch{return false}}
async function wrapW(prf){const m=await crypto.subtle.importKey('raw',prf,'HKDF',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:TE.encode('MyGallery vault key wrap v1')},m,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function prfEval(id,salt){const a=await navigator.credentials.get({publicKey:{challenge:rnd(32),allowCredentials:[{type:'public-key',id}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:salt}}}}});
 const r=a.getClientExtensionResults().prf;if(!r||!r.results||!r.results.first)throw Error('this device/browser returned no biometric-bound secret');return r.results.first}
async function bioKey(b){const w=await wrapW(await prfEval(b.credId,b.prfSalt));let raw;
 try{raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.iv},w,b.data)}catch{throw Error('stored biometric unlock does not match; use the passcode and re-enable it')}
 const k=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);const m=await get('meta','vault');
 try{await crypto.subtle.decrypt({name:'AES-GCM',iv:m.iv},k,m.data)}catch{throw Error('biometric key is out of date; use the passcode and re-enable it')}return k}
async function bioEnroll(){if(!await bioAvail())return toast('No fingerprint/face/screen-lock authenticator is available in this browser. Passcode stays available.',1);
 const m=await get('meta','vault');if(!m)return toast('Create the vault passcode first by opening the Private Vault',1);
 if(bioRec&&!confirm('Replace the existing biometric unlock?'))return;
 const pw=await askPw(false,'Confirm passcode to enable biometrics');if(pw==null||typeof pw==='object')return;
 let raw;try{const k=await derive(pw,m.salt,m.it,true);await crypto.subtle.decrypt({name:'AES-GCM',iv:m.iv},k,m.data);raw=await crypto.subtle.exportKey('raw',k)}catch{return toast('Wrong passcode',1)}
 try{const salt=rnd(32);const c=await navigator.credentials.create({publicKey:{rp:{name:'My Gallery'},user:{id:rnd(16),name:'my-gallery-vault',displayName:'My Gallery vault'},challenge:rnd(32),
   pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required',residentKey:'preferred'},timeout:60000,attestation:'none',extensions:{prf:{eval:{first:salt}}}}});
  const x=c.getClientExtensionResults().prf;if(!x||!x.enabled)throw Error('this browser/device does not support the WebAuthn PRF extension, which is required to unlock the vault without the passcode');
  const id=new Uint8Array(c.rawId),prf=x.results&&x.results.first?x.results.first:await prfEval(id,salt);
  const w=await wrapW(prf),iv=rnd(12),data=await crypto.subtle.encrypt({name:'AES-GCM',iv},w,raw),rec={k:'bio',credId:id,prfSalt:salt,iv,data};
  await put('meta',rec);bioRec=rec;toast('Biometric / device-lock unlock enabled')}
 catch(e){toast('Could not enable: '+msg(e)+'. Passcode still works.',1)}refreshAuth()}
async function refreshAuth(){const av=await bioAvail();$('#bioBtn').textContent=bioRec?'Disable biometrics':'Enable biometrics';
 $('#authInfo').textContent=bioRec?'Biometric unlock is on. Your device decides whether it uses fingerprint, face or screen lock. The passcode always works too.':av?'Biometric unlock is available but off. It may use fingerprint, face or your screen lock, depending on your device.':'Biometric unlock is not available in this browser/device. Use the passcode.'}
$('#bioBtn').onclick=async()=>{if(bioRec){await del('meta','bio');bioRec=null;toast('Biometric unlock disabled');refreshAuth()}else bioEnroll()};
$('#lockMin').onchange=e=>{localStorage.setItem('lockMin',e.target.value);resetLock()};
$('#cpBtn').onclick=async()=>{if(!await get('meta','vault'))return toast('No vault passcode yet. Open the Private Vault to create one.',1);
 ['#cpOld','#cpNew','#cpNew2'].forEach(i=>$(i).value='');$('#cpErr').textContent='';$('#cpDlg').showModal()};
$('#cpCancel').onclick=()=>$('#cpDlg').close();
// Changing the passcode changes the key, so every private record is re-encrypted, verified, then swapped in ONE transaction (all or nothing).
$('#cpOk').onclick=async()=>{const o=$('#cpOld').value,n=$('#cpNew').value,e=$('#cpErr');
 if(n.length<8){e.textContent='New passcode must be at least 8 characters';return}if(n!==$('#cpNew2').value){e.textContent='New passcodes do not match';return}
 const m=await get('meta','vault');let oldK;try{oldK=await derive(o,m.salt,m.it);await crypto.subtle.decrypt({name:'AES-GCM',iv:m.iv},oldK,m.data)}catch{e.textContent='Current passcode is wrong';return}
 $('#cpOk').disabled=true;e.textContent='Re-encrypting, please wait...';const hadBio=!!bioRec;
 try{const salt=rnd(16),nk=await derive(n,salt,PBKDF2_IT),out=[];
  for(const r of await all('vault')){const pl=await crypto.subtle.decrypt({name:'AES-GCM',iv:r.iv},oldK,r.data),iv=rnd(12),data=await crypto.subtle.encrypt({name:'AES-GCM',iv},nk,pl);
   if((await crypto.subtle.decrypt({name:'AES-GCM',iv},nk,data)).byteLength!==pl.byteLength)throw Error('Verification failed');out.push({...r,iv,data})}
  const civ=rnd(12),cd=await crypto.subtle.encrypt({name:'AES-GCM',iv:civ},nk,TE.encode('MYGALLERY-OK'));
  await new Promise((res,rej)=>{const t=db.transaction(['vault','meta'],'readwrite');out.forEach(r=>t.objectStore('vault').put(r));
   t.objectStore('meta').put({k:'vault',salt,it:PBKDF2_IT,iv:civ,data:cd});t.objectStore('meta').delete('bio');t.oncomplete=res;t.onerror=t.onabort=()=>rej(t.error||new Error('Database error'))});
  key=nk;bioRec=null;resetLock();$('#cpDlg').close();toast('Passcode changed'+(hadBio?'. Biometric unlock was reset; enable it again in Settings.':''));await refresh();refreshAuth()}
 catch(x){e.textContent='Change failed, nothing was modified: '+msg(x)}finally{$('#cpOk').disabled=false}};
(async()=>{try{db=await openDB();bioRec=(await get('meta','bio'))||null;await refresh()}catch(e){toast('Cannot open storage: '+msg(e),1)}
 if('serviceWorker'in navigator)navigator.serviceWorker.register('./service-worker.js').catch(()=>{})})();
