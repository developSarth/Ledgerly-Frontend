const API = import.meta.env.VITE_API_BASE_URL || '';
const TOKEN_KEY = 'ledgerly-api-access-token';
const REFRESH_KEY = 'ledgerly-api-refresh-token';
let accessToken = localStorage.getItem(TOKEN_KEY) || '';
let refreshToken = localStorage.getItem(REFRESH_KEY) || '';
export let cloudConfigured = false;
export let supabase;

async function request(path, options = {}, retry = true) {
  const headers = new Headers(options.headers || {});
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${API}${path}`, { ...options, headers });
  if (response.status === 401 && retry && refreshToken && path !== '/api/auth/refresh') {
    try {
      const refreshed = await fetch(`${API}/api/auth/refresh`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({refresh_token:refreshToken}) });
      if (refreshed.ok) { saveSession(await refreshed.json()); return request(path, options, false); }
    } catch { /* preserve the original authentication failure */ }
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const requestId = response.headers.get('X-Request-ID') || payload.request_id;
    const workflowRunId = response.headers.get('X-Workflow-Run-ID') || payload.workflow_run_id;
    const detail = Array.isArray(payload.detail)
      ? payload.detail.map(issue => `${(issue.loc || []).join('.')}: ${issue.msg}`).join('; ')
      : payload.detail || `Request failed (${response.status}).`;
    const refs = [requestId && `request ${requestId}`, workflowRunId && `run ${workflowRunId}`].filter(Boolean).join(', ');
    throw new Error(refs ? `${detail} (Reference: ${refs})` : detail);
  }
  return payload;
}
function saveSession(session) {
  accessToken = session?.access_token || '';
  refreshToken = session?.refresh_token || '';
  if (accessToken) localStorage.setItem(TOKEN_KEY, accessToken); else localStorage.removeItem(TOKEN_KEY);
  if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken); else localStorage.removeItem(REFRESH_KEY);
}
function normalizedSession(data) {
  if (data?.session) saveSession(data.session);
  return {data:{user:data?.user||null,session:data?.session||null},error:null};
}
try { cloudConfigured = (await request('/api/config', {}, false)).cloud_configured; } catch { cloudConfigured = false; }

supabase = {auth:{
  signInWithPassword: async ({email,password}) => normalizedSession(await request('/api/auth/sign-in',{method:'POST',body:JSON.stringify({email,password})},false)),
  signUp: async ({email,password,options}) => normalizedSession(await request('/api/auth/sign-up',{method:'POST',body:JSON.stringify({email,password,firm_name:options?.data?.firm_name||''})},false)),
  signOut: async () => {try {await request('/api/auth/sign-out',{method:'POST',body:'{}'},false);} finally {saveSession(null);}},
  getSession: async () => {if(!accessToken)return {data:{session:null},error:null};try{const {user}=await request('/api/auth/session');return {data:{session:{access_token:accessToken,refresh_token:refreshToken,user}},error:null};}catch{saveSession(null);return {data:{session:null},error:null};}}
}};
export async function getOrCreateFirm(user,firmName){const firm=await request('/api/cloud/firm');return firm||request('/api/cloud/firm',{method:'POST',body:JSON.stringify({name:firmName||user?.user_metadata?.firm_name||'My Law Firm'})});}
export async function importInvoiceBatch({fileName,rows,idempotencyKey}){return request('/api/cloud/imports',{method:'POST',headers:{'Idempotency-Key':idempotencyKey,'X-Workflow-Run-ID':idempotencyKey},body:JSON.stringify({file_name:fileName,rows})});}
export async function getFirmInvoices(){return request('/api/cloud/invoices');}
export async function getLatestImport(){return request('/api/cloud/latest-import');}
export async function getFirmEvents(){return request('/api/cloud/events');}
const workflowHeaders=()=>({'X-Workflow-Run-ID':crypto.randomUUID()});
export async function recordDemoOutreach({invoiceId,actionKey,messageType,simulatedDay}){return request('/api/cloud/outreach',{method:'POST',headers:workflowHeaders(),body:JSON.stringify({invoice_id:invoiceId,action_key:actionKey,message_type:messageType,simulated_day:simulatedDay})});}
export async function saveInvoiceReply({invoiceId,actionKey,replyType,summary,promiseDate,pauseUntil}){return request('/api/cloud/replies',{method:'POST',headers:workflowHeaders(),body:JSON.stringify({invoice_id:invoiceId,action_key:actionKey,reply_type:replyType,summary,promise_date:promiseDate||null,pause_until:pauseUntil||null})});}
export async function resumeInvoiceOutreach({invoiceId,actionKey}){return request('/api/cloud/resume',{method:'POST',headers:workflowHeaders(),body:JSON.stringify({invoice_id:invoiceId,action_key:actionKey})});}
export async function enableFirmAutomation(){return request('/api/cloud/automation/enable',{method:'POST',headers:workflowHeaders(),body:'{}'});}
