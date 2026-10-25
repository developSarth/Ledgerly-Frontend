# Ledgerly invoice follow-up agent

A browser demo for a law-firm receivables assistant. The workflow and message sending remain simulated. CSV invoice imports can be saved to Supabase when a project is configured; without Supabase configuration, the app uses fictional sample data in browser storage.

## Run locally

1. Install Node.js, then run `npm install`.
2. Copy `.env.example` to `.env.local` and add the Supabase project URL and publishable/anon key.
3. Apply `supabase/migrations/202610250001_invoice_csv_imports.sql` in the Supabase SQL Editor.
4. Start the app with `npm run dev` and open the local URL it prints.
5. Choose **Sign in to save**, create an account, and provide a firm name. Supabase email confirmation may need to be completed before signing in, depending on the project’s Auth settings.

The migration creates owner-scoped firm, import, invoice, and invoice-event tables, enables Row Level Security, and adds atomic CSV import, reply persistence, and demo-outreach recording functions. The client never needs a Supabase service-role key. Keep `.env.local` private and do not commit it.

## Demo flow

- Start with the sample invoices already shown, or sign in and import a CSV. With Supabase configured, invoice rows and import counts are saved in the database. Newly imported unpaid invoices appear in the plan; import itself does not count as contact.
- The **Connect email** button simulates a firm address connection for the frontend. It does not request mailbox permissions.
- Review **Today’s plan** and choose **Approve Today** to enable the ongoing follow-up policy and simulate today’s planned actions.
- Choose **Advance 1 week** to move simulated time forward and run the policy against the new date. Gentle follow-ups happen every seven days; after 21 days overdue, the firmer message waits for approval.
- Simulate a client reply to test promises, invoice-access questions, requests for help, disputes, payment claims, opt-outs, and out-of-office messages. Follow-up pauses where appropriate; with Supabase configured, reply summaries persist in the database.
- In local-only mode, mark an invoice paid to see the totals update. With Supabase configured, upload a refreshed CSV showing it as paid; that CSV remains the source of truth.

With Supabase configured, invoice workflow state and reply summaries persist across sessions. Outreach actions are recorded as simulations only. The database checks the latest CSV before recording an action: the invoice must be unpaid, included in the latest complete snapshot, and that snapshot must be no more than 24 hours old. A paid status, stale/incomplete snapshot, or invoice missing from the latest full CSV blocks the action. Re-upload the complete current invoice list to refresh status. No real email or SMS is sent, and there is no background scheduler; **Advance 1 week** is a demo control for moving simulated time.

The email connection control is a visual simulation only; it does not grant mailbox permissions. Sample data is fictional. In configured Supabase mode, imported invoice records, reply summaries, and workflow state persist in that Supabase project. Do not import real client data into a demo project until the firm has approved its data-handling and security setup.

## CSV columns

Required: invoice ID or number, client name, client email, amount or balance due, and due date. Optional: currency, issue date, status, and balance due. Common headers such as `Invoice Number`, `Client`, `Email`, `Total`, `Due Date`, `Balance Due`, and `Payment Status` are recognized. Duplicate invoice IDs and rows missing required values are skipped. Spreadsheet file parsing and Clio API access are not implemented.
