import { createClient } from '@supabase/supabase-js';

const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const cloudConfigured = Boolean(url && key && !url.includes('YOUR_PROJECT'));
export const supabase = cloudConfigured ? createClient(url, key) : null;

export async function importInvoiceBatch({ firmId, fileName, rows }) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('import_invoice_csv', {
    p_firm_id: firmId,
    p_file_name: fileName,
    p_rows: rows,
  });
  if (error) throw error;
  return data;
}

export async function getFirmInvoices(firmId) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase
    .from('invoices')
    .select('id, invoice_number, client_name, client_email, amount, amount_due, currency, issue_date, due_date, status, source_updated_at, last_import_id, outreach_state, first_contacted_on, last_contacted_on, next_action_on, pause_until, promise_date, reply_memory, last_action')
    .eq('firm_id', firmId)
    .order('due_date', { ascending: true });
  if (error) throw error;
  return data;
}

export async function getLatestImport(firmId) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase
    .from('invoice_imports')
    .select('id, file_name, imported_at, covers_all_invoices, received_rows, accepted_rows, duplicate_rows, invalid_rows')
    .eq('firm_id', firmId)
    .order('imported_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function getFirmEvents(firmId) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase
    .from('invoice_events')
    .select('event_type, summary, created_at, invoices(invoice_number)')
    .eq('firm_id', firmId)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) throw error;
  return data;
}

export async function recordDemoOutreach({ firmId, invoiceId, actionKey, messageType, simulatedDay }) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('record_demo_outreach', {
    p_firm_id: firmId,
    p_invoice_id: invoiceId,
    p_action_key: actionKey,
    p_message_type: messageType,
    p_simulated_day: simulatedDay,
  });
  if (error) throw error;
  return data;
}

export async function saveInvoiceReply({ firmId, invoiceId, actionKey, replyType, summary, promiseDate, pauseUntil }) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('save_invoice_reply', {
    p_firm_id: firmId,
    p_invoice_id: invoiceId,
    p_action_key: actionKey,
    p_reply_type: replyType,
    p_summary: summary,
    p_promise_date: promiseDate || null,
    p_pause_until: pauseUntil || null,
  });
  if (error) throw error;
  return data;
}

export async function resumeInvoiceOutreach({ firmId, invoiceId, actionKey }) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('resume_invoice_outreach', {
    p_firm_id: firmId,
    p_invoice_id: invoiceId,
    p_action_key: actionKey,
  });
  if (error) throw error;
  return data;
}

export async function getOrCreateFirm(user, firmName) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data: existing, error: readError } = await supabase
    .from('firms')
    .select('id, name, automation_enabled, timezone')
    .eq('owner_user_id', user.id)
    .maybeSingle();
  if (readError) throw readError;
  if (existing) return existing;
  const { data, error } = await supabase
    .from('firms')
    .insert({ owner_user_id: user.id, name: firmName })
    .select('id, name, automation_enabled, timezone')
    .single();
  if (error) throw error;
  return data;
}

export async function enableFirmAutomation(firmId) {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.rpc('enable_firm_automation', { p_firm_id: firmId });
  if (error) throw error;
  return data;
}
