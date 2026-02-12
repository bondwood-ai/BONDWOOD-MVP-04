/**
 * bondwood-payment-management-api
 * Independent worker for Bondwood Payment Management frontend.
 * Binds to the same D1 database but does NOT share code with bondwood-api.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-File-Name, X-Content-Type',
  'Access-Control-Expose-Headers': 'Content-Disposition',
  'Access-Control-Allow-Credentials': 'true',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS_HEADERS },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      // ── Health ──
      if (path === '/api/health') {
        // Add ?diag=1 for full diagnostics
        if (url.searchParams.get('diag') === '1') {
          const diag = { status: 'ok', worker: 'bondwood-payment-management-api', timestamp: new Date().toISOString() };
          diag.env_keys = Object.keys(env);
          diag.r2_bucket_bound = !!env.BUCKET;
          if (env.BUCKET) {
            try {
              const listed = await env.BUCKET.list({ limit: 1 });
              diag.r2_accessible = true;
              diag.r2_objects = listed.objects.map(o => o.key);
            } catch (e) { diag.r2_error = e.message; }
          }
          try {
            const { results } = await env.DB.prepare(
              'SELECT rfp_number, line_number, invoice_date, invoice_number FROM form_data LIMIT 10'
            ).all();
            diag.form_data_sample = results;
          } catch (e) { diag.form_data_error = e.message; }
          return json(diag);
        }
        return json({ status: 'ok', worker: 'bondwood-payment-management-api', version: 2, timestamp: new Date().toISOString() });
      }

      // ── Debug diagnostics ──
      if (path === '/api/debug/diag') {
        const diag = { path, method };

        // Check R2 binding
        diag.r2_bucket_bound = !!env.BUCKET;
        diag.env_keys = Object.keys(env);
        if (env.BUCKET) {
          try {
            const listed = await env.BUCKET.list({ limit: 1 });
            diag.r2_accessible = true;
            diag.r2_object_count_sample = listed.objects.length;
          } catch (e) {
            diag.r2_accessible = false;
            diag.r2_error = e.message;
          }
        }

        // Check invoice date query
        try {
          const { results } = await env.DB.prepare(`
            SELECT d.rfp_number, d.submission_date,
                   MAX(f.invoice_date) as latest_invoice_date,
                   COALESCE(SUM(f.total), 0) as total_amount
            FROM dashboard_data d
            LEFT JOIN form_data f ON d.rfp_number = f.rfp_number
            GROUP BY d.rfp_number
            LIMIT 5
          `).all();
          diag.rfp_sample = results;
        } catch (e) {
          diag.rfp_query_error = e.message;
        }

        // Check form_data invoice dates
        try {
          const { results } = await env.DB.prepare(
            'SELECT rfp_number, line_number, invoice_date, invoice_number FROM form_data LIMIT 10'
          ).all();
          diag.form_data_sample = results;
        } catch (e) {
          diag.form_data_error = e.message;
        }

        return json(diag);
      }

      // ── User Lookup (SSO) ──
      if (path === '/api/me' && method === 'GET') {
        return handleMe(request, env, url);
      }
      if (path === '/api/me/prefs' && method === 'GET') {
        return handleGetPrefs(request, env);
      }
      if (path === '/api/me/prefs' && method === 'PUT') {
        return handleSavePrefs(request, env);
      }

      // ── Vendors ──
      if (path === '/api/vendors' && method === 'GET') {
        return handleGetVendors(env, url);
      }
      if (path === '/api/vendors' && method === 'POST') {
        return handleCreateVendor(request, env);
      }
      if (path === '/api/vendors' && method === 'PUT') {
        return handleUpdateVendor(request, env);
      }
      if (path === '/api/vendors' && method === 'DELETE') {
        return handleDeleteVendor(request, env);
      }

      // ── Budget Codes ──
      if (path === '/api/budget-codes' && method === 'GET') {
        return handleGetBudgetCodes(env, url);
      }
      if (path === '/api/budget-codes/components' && method === 'GET') {
        return handleGetBudgetComponents(env);
      }
      if (path === '/api/budget-codes' && method === 'POST') {
        return handleCreateBudgetCode(request, env);
      }
      if (path === '/api/budget-codes' && method === 'PUT') {
        return handleUpdateBudgetCode(request, env);
      }
      if (path === '/api/budget-codes' && method === 'DELETE') {
        return handleDeleteBudgetCode(request, env);
      }

      // ── Districts ──
      if (path === '/api/districts' && method === 'GET') {
        return handleGetDistricts(env, url);
      }

      // ── RFPs ──
      if (path === '/api/rfps' && method === 'GET') {
        return handleListRFPs(env, url);
      }
      if (path === '/api/rfps' && method === 'POST') {
        return handleCreateRFP(request, env);
      }

      const rfpMatch = path.match(/^\/api\/rfps\/(\d+)$/);
      if (rfpMatch) {
        const rfpNumber = parseInt(rfpMatch[1]);
        if (method === 'GET') return handleGetRFP(rfpNumber, env);
        if (method === 'PUT') return handleUpdateRFP(rfpNumber, request, env);
        if (method === 'DELETE') return handleDeleteRFP(rfpNumber, env);
      }

      // ── Attachments ──
      const attListMatch = path.match(/^\/api\/rfps\/(\d+)\/attachments$/);
      if (attListMatch) {
        const rfpNumber = parseInt(attListMatch[1]);
        if (method === 'GET') return handleListAttachments(rfpNumber, env);
        if (method === 'POST') return handleUploadAttachment(rfpNumber, request, env);
      }

      const attItemMatch = path.match(/^\/api\/attachments\/(.+)$/);
      if (attItemMatch) {
        const key = decodeURIComponent(attItemMatch[1]);
        if (method === 'GET') return handleDownloadAttachment(key, env);
        if (method === 'DELETE') return handleDeleteAttachment(key, env);
      }

      // ── Audit Logs ──
      const auditMatch = path.match(/^\/api\/rfps\/(\d+)\/audit-log$/);
      if (auditMatch) {
        const rfpNumber = parseInt(auditMatch[1]);
        if (method === 'GET') return handleGetAuditLogs(rfpNumber, env);
        if (method === 'POST') return handleCreateAuditLog(rfpNumber, request, env);
      }

      // ── Users ──
      if (path === '/api/users' && method === 'GET') {
        return handleGetUsers(env);
      }
      if (path === '/api/users/status' && method === 'PUT') {
        return handleUpdateUserStatus(request, env);
      }

      // ── Profile ──
      if (path === '/api/profile' && method === 'PUT') {
        return handleUpdateProfile(request, env);
      }
      if (path === '/api/profile/picture' && method === 'POST') {
        return handleUploadProfilePicture(request, env);
      }
      const picMatch = path.match(/^\/api\/profile\/picture\/(.+)$/);
      if (picMatch && method === 'GET') {
        return handleGetProfilePicture(decodeURIComponent(picMatch[1]), env);
      }

      // ── Mileage ──
      if (path === '/api/mileage/sites' && method === 'GET') {
        return handleMileageSites(env);
      }
      if (path === '/api/mileage/distance' && method === 'GET') {
        return handleMileageDistance(env, url);
      }
      if (path === '/api/mileage/calculate' && method === 'POST') {
        return handleMileageCalculate(request, env);
      }

      // ── Seed Dummy Data ──
      if (path === '/api/seed-dummy' && method === 'POST') {
        return handleSeedDummy(request, env);
      }

      // ── Migrate ──
      if (path === '/api/migrate' && method === 'POST') {
        return handleMigrate(env);
      }

      if (path === '/api/migrate-budget-components' && method === 'POST') {
        return handleMigrateBudgetComponents(env);
      }

      // ── Extract invoice data from PDF via Gemini ──
      if (path === '/api/extract-invoice' && method === 'POST') {
        return handleExtractInvoice(request, env);
      }

      // ── Debug schema ──
      if (path === '/api/debug/schema' && method === 'GET') {
        const { results } = await env.DB.prepare("SELECT sql FROM sqlite_master WHERE type='table'").all();
        return json(results);
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Internal error', detail: e.message }, 500);
    }
  },

  /* ========================================
     SCHEDULED CLEANUP – Cron Trigger
     Purges soft-deleted RFPs (DB + R2) after 8 hours
     ======================================== */
  async scheduled(event, env, ctx) {
    const RETENTION_HOURS = 8;
    const cutoff = new Date(Date.now() - RETENTION_HOURS * 60 * 60 * 1000).toISOString();

    console.log(`[CLEANUP] Running scheduled purge. Cutoff: ${cutoff}`);

    // Find soft-deleted RFPs older than retention period
    const { results: stale } = await env.DB.prepare(
      'SELECT rfp_number FROM dashboard_data WHERE deleted_at IS NOT NULL AND deleted_at < ?'
    ).bind(cutoff).all();

    if (!stale.length) {
      console.log('[CLEANUP] No stale records to purge.');
      return;
    }

    console.log(`[CLEANUP] Purging ${stale.length} soft-deleted RFPs...`);
    let r2Deleted = 0;

    for (const row of stale) {
      const rfpNumber = row.rfp_number;

      // Clean up R2 attachments
      if (env.BUCKET) {
        try {
          const listed = await env.BUCKET.list({ prefix: `rfp/${rfpNumber}/` });
          if (listed.objects.length > 0) {
            await Promise.all(listed.objects.map(obj => env.BUCKET.delete(obj.key)));
            r2Deleted += listed.objects.length;
          }
        } catch (e) {
          console.error(`[CLEANUP] R2 error for RFP ${rfpNumber}:`, e.message);
        }
      }

      // Hard delete DB rows
      await env.DB.batch([
        env.DB.prepare('DELETE FROM audit_logs WHERE rfp_number = ?').bind(rfpNumber),
        env.DB.prepare('DELETE FROM mileage_trips WHERE rfp_number = ?').bind(rfpNumber),
        env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber),
        env.DB.prepare('DELETE FROM dashboard_data WHERE rfp_number = ?').bind(rfpNumber),
      ]);
    }

    console.log(`[CLEANUP] Done. Purged ${stale.length} RFPs, ${r2Deleted} R2 objects.`);
  },
};


/* ========================================
   USER LOOKUP
   ======================================== */
async function handleMe(request, env, url) {
  let email = url.searchParams.get('email');

  if (!email) {
    // Try Cf-Access header
    email = request.headers.get('Cf-Access-Authenticated-User-Email');
  }

  if (!email) {
    // Try CF_Authorization cookie
    const cookie = request.headers.get('Cookie') || '';
    const match = cookie.match(/CF_Authorization=([^;]+)/);
    if (match) {
      try {
        const payload = JSON.parse(atob(match[1].split('.')[1]));
        email = payload.email;
      } catch (e) {}
    }
  }

  if (!email) {
    return json({ error: 'No email provided' }, 400);
  }

  const { results } = await env.DB.prepare(
    'SELECT user_id, user_first_name, user_last_name, user_email, phone_number, department, title, profile_picture_key FROM user_data WHERE LOWER(user_email) = ?'
  ).bind(email.toLowerCase().trim()).all();

  if (!results.length) {
    return json({ error: 'User not found' }, 404);
  }

  const u = results[0];

  // Fetch roles
  let roles = [];
  try {
    const { results: roleResults } = await env.DB.prepare(
      'SELECT role FROM user_roles WHERE LOWER(user_email) = ? ORDER BY role'
    ).bind(email.toLowerCase().trim()).all();
    roles = roleResults.map(r => r.role);
  } catch (e) { /* user_roles table may not exist yet */ }

  return json({
    user_id: u.user_id,
    first_name: u.user_first_name,
    last_name: u.user_last_name,
    email: u.user_email,
    phone_number: u.phone_number || '',
    department: u.department || '',
    title: u.title || '',
    profile_picture_key: u.profile_picture_key || null,
    roles,
  });
}


/* ========================================
   USER PREFERENCES
   ======================================== */
function getEmailFromRequest(request) {
  let email = request.headers.get('Cf-Access-Authenticated-User-Email');
  if (!email) {
    const cookie = request.headers.get('Cookie') || '';
    const match = cookie.match(/CF_Authorization=([^;]+)/);
    if (match) {
      try {
        const payload = JSON.parse(atob(match[1].split('.')[1]));
        email = payload.email;
      } catch (e) {}
    }
  }
  return email ? email.toLowerCase().trim() : null;
}

async function handleGetPrefs(request, env) {
  const email = getEmailFromRequest(request);
  if (!email) return json({ error: 'No email' }, 400);

  try {
    const { results } = await env.DB.prepare(
      'SELECT dashboard_prefs FROM user_data WHERE LOWER(user_email) = ?'
    ).bind(email).all();

    if (!results.length) return json({ prefs: null });

    const raw = results[0].dashboard_prefs;
    return json({ prefs: raw ? JSON.parse(raw) : null });
  } catch (e) {
    return json({ prefs: null });
  }
}

async function handleSavePrefs(request, env) {
  const email = getEmailFromRequest(request);
  if (!email) return json({ error: 'No email' }, 400);

  const body = await request.json();
  const prefsJson = JSON.stringify(body.prefs || {});

  await env.DB.prepare(
    'UPDATE user_data SET dashboard_prefs = ? WHERE LOWER(user_email) = ?'
  ).bind(prefsJson, email).run();

  return json({ message: 'Preferences saved' });
}


/* ========================================
   VENDORS
   ======================================== */
async function handleGetVendors(env, url) {
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '2000'), 5000);
  const offset = (page - 1) * limit;

  const { results } = await env.DB.prepare(
    'SELECT vendor_name, vendor_number, vendor_address, vendor_city, vendor_state, vendor_zip FROM vendor_data ORDER BY vendor_name LIMIT ? OFFSET ?'
  ).bind(limit, offset).all();

  const { results: countResult } = await env.DB.prepare('SELECT COUNT(*) as total FROM vendor_data').all();
  const total = countResult[0]?.total || 0;

  return json({ vendors: results, total, page, limit });
}


/* ========================================
   BUDGET CODES
   ======================================== */
async function handleGetBudgetCodes(env, url) {
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '2000'), 5000);
  const offset = (page - 1) * limit;

  const { results } = await env.DB.prepare(
    'SELECT * FROM budget_code ORDER BY budget_code LIMIT ? OFFSET ?'
  ).bind(limit, offset).all();

  const { results: countResult } = await env.DB.prepare('SELECT COUNT(*) as total FROM budget_code').all();
  const total = countResult[0]?.total || 0;

  return json({ budget_codes: results, total, page, limit });
}


/* ========================================
   VENDORS – CREATE
   ======================================== */
async function handleCreateVendor(request, env) {
  const body = await request.json();
  const { vendor_name, vendor_number, vendor_address, vendor_city, vendor_state, vendor_zip } = body;

  if (!vendor_name || !vendor_number) {
    return json({ error: 'vendor_name and vendor_number are required' }, 400);
  }

  // Check for duplicate vendor_number
  const { results: existing } = await env.DB.prepare(
    'SELECT vendor_number FROM vendor_data WHERE vendor_number = ?'
  ).bind(vendor_number.trim()).all();

  if (existing.length) {
    return json({ error: `Vendor number ${vendor_number} already exists` }, 409);
  }

  await env.DB.prepare(
    'INSERT INTO vendor_data (vendor_name, vendor_number, vendor_address, vendor_city, vendor_state, vendor_zip) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(
    vendor_name.trim(),
    vendor_number.trim(),
    vendor_address?.trim() || null,
    vendor_city?.trim() || null,
    vendor_state?.trim() || null,
    vendor_zip?.trim() || null,
  ).run();

  return json({ message: 'Vendor created', vendor_number: vendor_number.trim() }, 201);
}


/* ========================================
   VENDORS – DELETE
   ======================================== */
async function handleDeleteVendor(request, env) {
  const body = await request.json();
  const { vendor_number } = body;

  if (!vendor_number) return json({ error: 'vendor_number is required' }, 400);

  await env.DB.prepare('DELETE FROM vendor_data WHERE vendor_number = ?').bind(vendor_number.trim()).run();
  return json({ message: 'Vendor deleted', vendor_number });
}


/* ========================================
   BUDGET CODES – CREATE
   ======================================== */
async function handleCreateBudgetCode(request, env) {
  const body = await request.json();
  const { budget_code, account_code, fund, organization, program, finance, course } = body;

  if (!budget_code || !account_code) {
    return json({ error: 'budget_code and account_code are required' }, 400);
  }

  // Check for duplicate
  const { results: existing } = await env.DB.prepare(
    'SELECT budget_code FROM budget_code WHERE budget_code = ? AND account_code = ?'
  ).bind(budget_code.trim(), account_code.trim()).all();

  if (existing.length) {
    return json({ error: `Budget code ${budget_code} with account ${account_code} already exists` }, 409);
  }

  await env.DB.prepare(
    'INSERT INTO budget_code (budget_code, account_code, fund, organization, program, finance, course) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    budget_code.trim(),
    account_code.trim(),
    fund?.trim() || null,
    organization?.trim() || null,
    program?.trim() || null,
    finance?.trim() || null,
    course?.trim() || null,
  ).run();

  return json({ message: 'Budget code created', budget_code: budget_code.trim(), account_code: account_code.trim() }, 201);
}


/* ========================================
   BUDGET CODES – DELETE
   ======================================== */
async function handleDeleteBudgetCode(request, env) {
  const body = await request.json();
  const { budget_code, account_code } = body;

  if (!budget_code) return json({ error: 'budget_code is required' }, 400);

  if (account_code) {
    await env.DB.prepare('DELETE FROM budget_code WHERE budget_code = ? AND account_code = ?')
      .bind(budget_code.trim(), account_code.trim()).run();
  } else {
    await env.DB.prepare('DELETE FROM budget_code WHERE budget_code = ?')
      .bind(budget_code.trim()).run();
  }

  return json({ message: 'Budget code deleted', budget_code });
}


/* ========================================
   VENDORS – UPDATE
   ======================================== */
async function handleUpdateVendor(request, env) {
  const body = await request.json();
  const { vendor_number, vendor_name, vendor_address, vendor_city, vendor_state, vendor_zip } = body;

  if (!vendor_number) return json({ error: 'vendor_number is required' }, 400);

  await env.DB.prepare(
    'UPDATE vendor_data SET vendor_name = ?, vendor_address = ?, vendor_city = ?, vendor_state = ?, vendor_zip = ? WHERE vendor_number = ?'
  ).bind(
    vendor_name?.trim() || '',
    vendor_address?.trim() || null,
    vendor_city?.trim() || null,
    vendor_state?.trim() || null,
    vendor_zip?.trim() || null,
    vendor_number.trim(),
  ).run();

  return json({ message: 'Vendor updated', vendor_number });
}


/* ========================================
   BUDGET CODES – UPDATE
   ======================================== */
async function handleUpdateBudgetCode(request, env) {
  const body = await request.json();
  const { original_budget_code, original_account_code, budget_code, account_code, fund, organization, program, finance, course } = body;

  if (!original_budget_code || !original_account_code) {
    return json({ error: 'original_budget_code and original_account_code are required' }, 400);
  }

  await env.DB.prepare(
    'UPDATE budget_code SET budget_code = ?, account_code = ?, fund = ?, organization = ?, program = ?, finance = ?, course = ? WHERE budget_code = ? AND account_code = ?'
  ).bind(
    budget_code?.trim() || original_budget_code,
    account_code?.trim() || original_account_code,
    fund?.trim() || null,
    organization?.trim() || null,
    program?.trim() || null,
    finance?.trim() || null,
    course?.trim() || null,
    original_budget_code.trim(),
    original_account_code.trim(),
  ).run();

  return json({ message: 'Budget code updated' });
}


/* ========================================
   BUDGET CODES – COMPONENTS (unique values)
   ======================================== */
async function handleGetBudgetComponents(env) {
  const [funds, orgs, programs, finances, courses, accounts] = await Promise.all([
    env.DB.prepare('SELECT DISTINCT fund FROM budget_code WHERE fund IS NOT NULL ORDER BY fund').all(),
    env.DB.prepare('SELECT DISTINCT organization FROM budget_code WHERE organization IS NOT NULL ORDER BY organization').all(),
    env.DB.prepare('SELECT DISTINCT program FROM budget_code WHERE program IS NOT NULL ORDER BY program').all(),
    env.DB.prepare('SELECT DISTINCT finance FROM budget_code WHERE finance IS NOT NULL ORDER BY finance').all(),
    env.DB.prepare('SELECT DISTINCT course FROM budget_code WHERE course IS NOT NULL ORDER BY course').all(),
    env.DB.prepare('SELECT DISTINCT account_code FROM budget_code WHERE account_code IS NOT NULL ORDER BY account_code').all(),
  ]);

  return json({
    funds: funds.results.map(r => (r.fund || '').toString().trim()),
    organizations: orgs.results.map(r => (r.organization || '').toString().trim()),
    programs: programs.results.map(r => (r.program || '').toString().trim()),
    finances: finances.results.map(r => (r.finance || '').toString().trim()),
    courses: courses.results.map(r => (r.course || '').toString().trim()),
    accounts: accounts.results.map(r => (r.account_code || '').toString().trim()),
  });
}


/* ========================================
   DISTRICTS
   ======================================== */
async function handleGetDistricts(env, url) {
  try {
    const { results } = await env.DB.prepare('SELECT * FROM district_metadata').all();
    return json(results);
  } catch (e) {
    return json({ error: 'Districts query failed', detail: e.message }, 500);
  }
}


/* ========================================
   RFPs – LIST
   ======================================== */
async function handleListRFPs(env, url) {
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '250'), 1000);
  const offset = (page - 1) * limit;
  const status = url.searchParams.get('status') || 'all';
  const search = url.searchParams.get('search') || '';
  const sort = url.searchParams.get('sort') || 'rfp_number';
  const dir = (url.searchParams.get('dir') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  const allowedSorts = ['rfp_number', 'submission_date', 'submitter_name', 'vendor_name', 'status'];
  const sortCol = allowedSorts.includes(sort) ? sort : 'rfp_number';

  let where = ['d.deleted_at IS NULL'];
  let params = [];

  if (status && status !== 'all') {
    where.push('d.status = ?');
    params.push(status);
  }

  if (search) {
    where.push(`(d.submitter_name LIKE ? OR d.vendor_name LIKE ? OR CAST(d.rfp_number AS TEXT) LIKE ?)`);
    const s = `%${search}%`;
    params.push(s, s, s);
  }

  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  // Get totals
  const { results: countRows } = await env.DB.prepare(
    `SELECT COUNT(*) as total FROM dashboard_data d ${whereClause}`
  ).bind(...params).all();
  const total = countRows[0]?.total || 0;

  // Get RFPs with line item totals + mileage
  const { results } = await env.DB.prepare(`
    SELECT d.*, COALESCE(SUM(f.total), 0) + COALESCE(d.mileage_total, 0) as total_amount,
           MAX(f.invoice_date) as latest_invoice_date
    FROM dashboard_data d
    LEFT JOIN form_data f ON d.rfp_number = f.rfp_number
    ${whereClause}
    GROUP BY d.rfp_number
    ORDER BY d.${sortCol} ${dir}
    LIMIT ? OFFSET ?
  `).bind(...params, limit, offset).all();

  return json({ rfps: results, total, page, limit });
}


/* ========================================
   RFPs – GET SINGLE
   ======================================== */
async function handleGetRFP(rfpNumber, env) {
  const { results: header } = await env.DB.prepare(
    'SELECT * FROM dashboard_data WHERE rfp_number = ? AND deleted_at IS NULL'  ).bind(rfpNumber).all();

  if (!header.length) {
    return json({ error: 'RFP not found' }, 404);
  }

  const { results: lineItems } = await env.DB.prepare(
    'SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number'
  ).bind(rfpNumber).all();

  let mileageTrips = [];
  try {
    const { results: trips } = await env.DB.prepare(
      'SELECT * FROM mileage_trips WHERE rfp_number = ? ORDER BY trip_number'
    ).bind(rfpNumber).all();
    mileageTrips = trips;
  } catch (e) { /* table may not exist yet */ }

  let auditLogs = [];
  try {
    const { results: logs } = await env.DB.prepare(
      'SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY created_at ASC, id ASC'
    ).bind(rfpNumber).all();
    auditLogs = logs;
  } catch (e) { /* table may not exist yet */ }

  return json({ ...header[0], lineItems, mileageTrips, auditLogs });
}


/* ========================================
   RFPs – CREATE
   ======================================== */
async function handleCreateRFP(request, env) {
  const body = await request.json();

  // Atomic next RFP number from sequences table
  const { results: seqRows } = await env.DB.prepare(
    "UPDATE sequences SET value = value + 1 WHERE name = 'rfp_no' RETURNING value"
  ).all();

  if (!seqRows.length) {
    return json({ error: 'Sequence rfp_no not found. Run POST /api/migrate first.' }, 500);
  }

  const nextRfp = seqRows[0].value;

  const status = body.status || 'draft';
  const submissionDate = body.submission_date || new Date().toISOString().split('T')[0];
  const performer = body.submitter_name || 'Unknown';

  const headerStmt = env.DB.prepare(`
    INSERT INTO dashboard_data (
      rfp_number, submitter_name, submitter_id, budget_approver,
      submission_date, request_type, vendor_name, vendor_number,
      vendor_address, invoice_number, employee_name, employee_id,
      description, status, assigned_to, ap_batch, mileage_total, creation_source
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const headerParams = [
    nextRfp,
    body.submitter_name || '',
    body.submitter_id || '',
    body.budget_approver || null,
    submissionDate,
    body.request_type || 'vendor',
    body.vendor_name || null,
    body.vendor_number || null,
    body.vendor_address || null,
    body.invoice_number || null,
    body.employee_name || null,
    body.employee_id || null,
    body.description || null,
    status,
    body.assigned_to || null,
    body.ap_batch || null,
    body.mileage_total || 0,
    body.creation_source || null,
  ];

  const statements = [headerStmt.bind(...headerParams)];

  const newItems = (body.lineItems || []).filter(i => i.description);
  const newTrips = body.mileageTrips || [];

  if (newItems.length) {
    for (const item of newItems) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO form_data (
            rfp_number, line_number, description, fund, organization,
            program, finance, object, quantity, unit_price, total,
            invoice_number, invoice_date, budget_code, account_code
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          nextRfp,
          item.line_number || 0,
          item.description || '',
          item.fund || null,
          item.organization || null,
          item.program || null,
          item.finance || null,
          item.object || item.account_code || null,
          item.quantity || 1,
          item.unit_price || item.total || 0,
          item.total || 0,
          item.invoice_number || null,
          item.invoice_date || null,
          item.budget_code || null,
          item.account_code || null,
        )
      );
    }
  }

  if (newTrips.length) {
    for (const trip of newTrips) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO mileage_trips (
            rfp_number, trip_number, trip_date, from_location, to_location,
            miles, rate, amount, budget_code, account_code
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          nextRfp,
          trip.trip_number || 0,
          trip.trip_date || null,
          trip.from_location || null,
          trip.to_location || null,
          trip.miles || 0,
          trip.rate || 0,
          trip.amount || 0,
          trip.budget_code || null,
          trip.account_code || null,
        )
      );
    }
  }

  // Build audit description
  const typeLabel = (body.request_type === 'reimbursement') ? 'Employee Reimbursement' : (body.vendor_name || 'Vendor Payment');
  const itemTotal = newItems.reduce((s, i) => s + (i.total || 0), 0);
  const mileageTotal = body.mileage_total || 0;
  const grandTotal = itemTotal + mileageTotal;
  const statusVerb = status === 'submitted' ? 'submitted' : 'created a draft';

  let auditDesc = `<strong>${performer}</strong> ${statusVerb} request for payment with <strong>${typeLabel}</strong> for <strong>$${grandTotal.toFixed(2)}</strong>`;
  const detailParts = [];
  if (newItems.length) detailParts.push(`${newItems.length} line item${newItems.length > 1 ? 's' : ''} ($${itemTotal.toFixed(2)})`);
  if (newTrips.length) detailParts.push(`${newTrips.length} mileage trip${newTrips.length > 1 ? 's' : ''} ($${mileageTotal.toFixed(2)})`);
  if (detailParts.length) auditDesc += ` — ${detailParts.join(', ')}`;

  const sourceLabel = body.creation_source === 'import' ? ' using the <strong>Import</strong> function'
      : body.creation_source === 'capture' ? ' using the <strong>Capture Invoice</strong> function' : '';
  auditDesc += sourceLabel;

  const now = new Date().toISOString();
  statements.push(
    env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(nextRfp, status === 'submitted' ? 'submitted' : 'draft-created', auditDesc, performer, now)
  );

  await env.DB.batch(statements);

  return json({ rfp_number: nextRfp, status, message: 'RFP created' }, 201);
}


/* ========================================
   RFPs – UPDATE
   ======================================== */
async function handleUpdateRFP(rfpNumber, request, env) {
  const body = await request.json();
  const performer = body.submitter_name || 'Unknown';
  const now = new Date().toISOString();

  // ── Read existing state BEFORE making changes ──
  const { results: existingHeader } = await env.DB.prepare(
    'SELECT * FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!existingHeader.length) {
    return json({ error: 'RFP not found' }, 404);
  }
  const oldHeader = existingHeader[0];

  let oldItems = [];
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number'
    ).bind(rfpNumber).all();
    oldItems = results.filter(i => i.description);
  } catch (e) {}

  let oldTrips = [];
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM mileage_trips WHERE rfp_number = ? ORDER BY trip_number'
    ).bind(rfpNumber).all();
    oldTrips = results;
  } catch (e) {}

  // ── Build update statements ──
  const updatableFields = [
    'submitter_name', 'submitter_id', 'budget_approver', 'submission_date',
    'request_type', 'vendor_name', 'vendor_number', 'vendor_address',
    'invoice_number', 'employee_name', 'employee_id', 'description',
    'status', 'assigned_to', 'ap_batch', 'mileage_total',
  ];

  const setClauses = [];
  const setParams = [];

  for (const field of updatableFields) {
    if (body[field] !== undefined) {
      setClauses.push(`${field} = ?`);
      setParams.push(body[field]);
    }
  }

  const statements = [];

  if (setClauses.length) {
    statements.push(
      env.DB.prepare(
        `UPDATE dashboard_data SET ${setClauses.join(', ')} WHERE rfp_number = ?`
      ).bind(...setParams, rfpNumber)
    );
  }

  // Replace line items if provided
  const newItems = body.lineItems ? body.lineItems.filter(i => i.description) : null;
  if (body.lineItems) {
    statements.push(
      env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber)
    );

    for (const item of (body.lineItems || [])) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO form_data (
            rfp_number, line_number, description, fund, organization,
            program, finance, object, quantity, unit_price, total,
            invoice_number, invoice_date, budget_code, account_code
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          rfpNumber,
          item.line_number || 0,
          item.description || '',
          item.fund || null,
          item.organization || null,
          item.program || null,
          item.finance || null,
          item.object || item.account_code || null,
          item.quantity || 1,
          item.unit_price || item.total || 0,
          item.total || 0,
          item.invoice_number || null,
          item.invoice_date || null,
          item.budget_code || null,
          item.account_code || null,
        )
      );
    }
  }

  // Replace mileage trips if provided
  const newTrips = body.mileageTrips || null;
  if (body.mileageTrips) {
    statements.push(
      env.DB.prepare('DELETE FROM mileage_trips WHERE rfp_number = ?').bind(rfpNumber)
    );

    for (const trip of body.mileageTrips) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO mileage_trips (
            rfp_number, trip_number, trip_date, from_location, to_location,
            miles, rate, amount, budget_code, account_code
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          rfpNumber,
          trip.trip_number || 0,
          trip.trip_date || null,
          trip.from_location || null,
          trip.to_location || null,
          trip.miles || 0,
          trip.rate || 0,
          trip.amount || 0,
          trip.budget_code || null,
          trip.account_code || null,
        )
      );
    }
  }

  // ── Detect changes and build audit entries ──
  const auditEntries = buildAuditEntries(oldHeader, oldItems, oldTrips, body, newItems, newTrips, performer);

  for (const entry of auditEntries) {
    statements.push(
      env.DB.prepare(
        'INSERT INTO audit_logs (rfp_number, action, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(rfpNumber, entry.action, entry.description, performer, now)
    );
  }

  if (statements.length) {
    await env.DB.batch(statements);
  }

  return json({ rfp_number: rfpNumber, message: 'RFP updated' });
}


/* ========================================
   AUDIT – SERVER-SIDE CHANGE DETECTION
   ======================================== */
function buildAuditEntries(oldHeader, oldItems, oldTrips, body, newItems, newTrips, performer) {
  const entries = [];
  const p = `<strong>${performer}</strong>`;
  const fmt = (n) => '$' + (n || 0).toFixed(2);

  // ── Status change ──
  if (body.status && body.status !== oldHeader.status) {
    if (body.status === 'submitted' && oldHeader.status === 'draft') {
      const typeLabel = (body.request_type || oldHeader.request_type) === 'reimbursement'
        ? 'Employee Reimbursement' : (body.vendor_name || oldHeader.vendor_name || 'Vendor Payment');
      const itemTotal = newItems ? newItems.reduce((s, i) => s + (i.total || 0), 0) : oldItems.reduce((s, i) => s + (i.total || 0), 0);
      const mTotal = body.mileage_total !== undefined ? body.mileage_total : (oldHeader.mileage_total || 0);
      entries.push({
        action: 'submitted',
        description: `${p} submitted request for payment with <strong>${typeLabel}</strong> for <strong>${fmt(itemTotal + mTotal)}</strong>`
      });
      return entries; // Status change to submitted is the primary event
    }
  }

  // ── Line item changes ──
  if (newItems !== null) {
    const oldDescs = new Map();
    oldItems.forEach(i => oldDescs.set(i.description, i));

    const newDescs = new Map();
    newItems.forEach(i => newDescs.set(i.description, i));

    // Added items
    const added = newItems.filter(i => !oldDescs.has(i.description));
    for (const item of added) {
      entries.push({
        action: 'item-added',
        description: `${p} added line item: <strong>${item.description}</strong> — ${fmt(item.total)}${item.budget_code ? ' (Budget: ' + item.budget_code + ')' : ''}`
      });
    }

    // Removed items
    const removed = oldItems.filter(i => !newDescs.has(i.description));
    for (const item of removed) {
      entries.push({
        action: 'item-removed',
        description: `${p} removed line item: <strong>${item.description}</strong> — ${fmt(item.total)}`
      });
    }

    // Modified items (same description, different amount/budget)
    for (const [desc, newItem] of newDescs) {
      const oldItem = oldDescs.get(desc);
      if (!oldItem) continue; // already handled as "added"
      const changes = [];
      if (Math.abs((oldItem.total || 0) - (newItem.total || 0)) > 0.005) {
        changes.push(`amount ${fmt(oldItem.total)} → ${fmt(newItem.total)}`);
      }
      if ((oldItem.budget_code || '') !== (newItem.budget_code || '') && newItem.budget_code) {
        changes.push(`budget code → ${newItem.budget_code}`);
      }
      if ((oldItem.account_code || '') !== (newItem.account_code || '') && newItem.account_code) {
        changes.push(`account → ${newItem.account_code}`);
      }
      if (changes.length) {
        entries.push({
          action: 'item-modified',
          description: `${p} modified line item <strong>${desc}</strong>: ${changes.join(', ')}`
        });
      }
    }
  }

  // ── Mileage trip changes ──
  if (newTrips !== null) {
    const tripKey = (t) => `${t.from_location || ''}→${t.to_location || ''}`;

    const oldTripMap = new Map();
    oldTrips.forEach(t => oldTripMap.set(tripKey(t), t));

    const newTripMap = new Map();
    newTrips.forEach(t => newTripMap.set(tripKey(t), t));

    // Added trips
    for (const trip of newTrips) {
      if (!oldTripMap.has(tripKey(trip))) {
        entries.push({
          action: 'trip-added',
          description: `${p} added mileage trip: <strong>${trip.from_location || '?'}</strong> → <strong>${trip.to_location || '?'}</strong> (${trip.miles || 0} mi, ${fmt(trip.amount)})`
        });
      }
    }

    // Removed trips
    for (const trip of oldTrips) {
      if (!newTripMap.has(tripKey(trip))) {
        entries.push({
          action: 'trip-removed',
          description: `${p} removed mileage trip: <strong>${trip.from_location || '?'}</strong> → <strong>${trip.to_location || '?'}</strong> (${trip.miles || 0} mi, ${fmt(trip.amount)})`
        });
      }
    }

    // Modified trips (same route, different miles/amount)
    for (const [key, newTrip] of newTripMap) {
      const oldTrip = oldTripMap.get(key);
      if (!oldTrip) continue;
      const changes = [];
      if (Math.abs((oldTrip.miles || 0) - (newTrip.miles || 0)) > 0.05) {
        changes.push(`miles ${oldTrip.miles} → ${newTrip.miles}`);
      }
      if (Math.abs((oldTrip.amount || 0) - (newTrip.amount || 0)) > 0.005) {
        changes.push(`amount ${fmt(oldTrip.amount)} → ${fmt(newTrip.amount)}`);
      }
      if (changes.length) {
        entries.push({
          action: 'trip-modified',
          description: `${p} modified mileage trip <strong>${newTrip.from_location}</strong> → <strong>${newTrip.to_location}</strong>: ${changes.join(', ')}`
        });
      }
    }
  }

  // ── Header field changes ──
  if (body.vendor_name && body.vendor_name !== (oldHeader.vendor_name || '')) {
    entries.push({ action: 'field-changed', description: `${p} changed vendor to <strong>${body.vendor_name}</strong>` });
  }
  if (body.description !== undefined && body.description !== (oldHeader.description || '')) {
    entries.push({ action: 'field-changed', description: `${p} updated the description` });
  }
  if (body.assigned_to && body.assigned_to !== (oldHeader.assigned_to || '')) {
    entries.push({ action: 'field-changed', description: `${p} assigned to <strong>${body.assigned_to}</strong>` });
  }

  // ── Fallback if nothing specific detected ──
  if (entries.length === 0) {
    entries.push({ action: 'draft-updated', description: `${p} saved the draft` });
  }

  return entries;
}


/* ========================================
   RFPs – DELETE
   ======================================== */
async function handleDeleteRFP(rfpNumber, env) {
  const { results: existing } = await env.DB.prepare(
    'SELECT id FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!existing.length) {
    return json({ error: 'RFP not found' }, 404);
  }

  // Soft delete — mark with timestamp, cleanup cron purges after 8 hours
  await env.DB.prepare(
    'UPDATE dashboard_data SET deleted_at = ? WHERE rfp_number = ?'
  ).bind(new Date().toISOString(), rfpNumber).run();

  return json({ message: 'RFP deleted', rfp_number: rfpNumber });
}


/* ========================================
   MIGRATE
   ======================================== */
/* ========================================
   SEED DUMMY DATA
   ======================================== */
async function handleSeedDummy(request, env) {
  const COUNT = 550;

  // Clear existing data first
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM form_data'),
      env.DB.prepare('DELETE FROM dashboard_data'),
    ]);
  } catch (e) { /* tables might not exist yet */ }

  // ── Reference data pools ──
  const submitters = [
    { name: 'Sarah Johnson', id: 'sjohnson' },
    { name: 'Michael Chen', id: 'mchen' },
    { name: 'Emily Rodriguez', id: 'erodriguez' },
    { name: 'David Kim', id: 'dkim' },
    { name: 'Jessica Martinez', id: 'jmartinez' },
    { name: 'Robert Anderson', id: 'randerson' },
    { name: 'Amanda Thompson', id: 'athompson' },
    { name: 'James Wilson', id: 'jwilson' },
    { name: 'Lisa Park', id: 'lpark' },
    { name: 'Thomas Brown', id: 'tbrown' },
    { name: 'Rachel Green', id: 'rgreen' },
    { name: 'Kevin Nguyen', id: 'knguyen' },
    { name: 'Maria Garcia', id: 'mgarcia' },
    { name: 'Daniel Lee', id: 'dlee' },
    { name: 'Stephanie White', id: 'swhite' },
  ];

  const approvers = [
    'Dr. Patricia Edwards', 'Mark Sullivan', 'Natalie Foster', 'Principal Jeff Howard',
    'Karen Mitchell', 'Director Amy Lin', 'Brian Cooper', 'Superintendent Davis',
  ];

  const vendors = [
    { name: 'BSN Sports, LLC', number: '10245', address: '1901 Diplomat Dr, Dallas, TX 75234' },
    { name: 'School Specialty', number: '10312', address: '625 Mount Auburn St, Greenville, WI 54942' },
    { name: 'Lakeshore Learning', number: '10187', address: '2695 E Dominguez St, Carson, CA 90895' },
    { name: 'Staples Business', number: '10401', address: '500 Staples Dr, Framingham, MA 01702' },
    { name: 'Scholastic Inc.', number: '10098', address: '557 Broadway, New York, NY 10012' },
    { name: 'Amazon Business', number: '10550', address: 'PO Box 81226, Seattle, WA 98108' },
    { name: 'Nasco Education', number: '10623', address: '901 Janesville Ave, Fort Atkinson, WI 53538' },
    { name: 'Pearson Education', number: '10074', address: '221 River St, Hoboken, NJ 07030' },
    { name: 'Carolina Biological', number: '10789', address: '2700 York Rd, Burlington, NC 27215' },
    { name: 'Flinn Scientific', number: '10834', address: '770 N Raddant Rd, Batavia, IL 60510' },
    { name: 'Gopher Sport', number: '10290', address: '220 24th Ave NW, Owatonna, MN 55060' },
    { name: 'CDW Government', number: '10456', address: '200 N Milwaukee Ave, Vernon Hills, IL 60061' },
    { name: 'Houghton Mifflin', number: '10112', address: '125 High St, Boston, MA 02110' },
    { name: 'Edmentum Inc.', number: '10667', address: '5600 W 83rd St, Bloomington, MN 55437' },
    { name: 'Grainger Inc.', number: '10901', address: '100 Grainger Pkwy, Lake Forest, IL 60045' },
    { name: 'Home Depot Pro', number: '10955', address: '3097 Satellite Blvd, Duluth, GA 30096' },
    { name: 'Menards Inc.', number: '11002', address: '5101 Menard Dr, Eau Claire, WI 54703' },
    { name: 'TIES Education', number: '11089', address: '1667 Snelling Ave N, St. Paul, MN 55108' },
    { name: 'Apple Inc.', number: '11150', address: 'One Apple Park Way, Cupertino, CA 95014' },
    { name: 'Dell Technologies', number: '11203', address: '1 Dell Way, Round Rock, TX 78682' },
  ];

  const employees = [
    { name: 'Sarah Johnson', id: 'EMP001' }, { name: 'Michael Chen', id: 'EMP002' },
    { name: 'Emily Rodriguez', id: 'EMP003' }, { name: 'David Kim', id: 'EMP004' },
    { name: 'Jessica Martinez', id: 'EMP005' }, { name: 'Robert Anderson', id: 'EMP006' },
    { name: 'Amanda Thompson', id: 'EMP007' }, { name: 'James Wilson', id: 'EMP008' },
  ];

  const budgetCodes = [
    '01005203000000', '01024610000000', '01010305000000', '01050201000000',
    '01031502000000', '01042001000000', '01060103000000', '01015404000000',
    '01070802000000', '01025301000000', '01033605000000', '01041204000000',
  ];
  const accountCodes = ['401', '366', '368', '430', '460', '350', '510', '433', '461', '320'];

  const descriptions = [
    'Classroom supplies for Q3', 'Science lab equipment', 'Athletic uniforms - Fall season',
    'Textbook order - AP courses', 'Technology refresh - Chromebooks', 'Art supplies replenishment',
    'Custodial cleaning supplies', 'Office paper and toner', 'Library book acquisition',
    'Music department instruments', 'Playground equipment repair', 'HVAC filter replacement',
    'Professional development materials', 'Student assessment software', 'Cafeteria kitchen supplies',
    'Security camera maintenance', 'Furniture replacement - Room 204', 'Graphic calculators - Math dept',
    'Welding shop consumables', 'Nurse office medical supplies', 'Printing and copying services',
    'Field trip transportation', 'Guest speaker honorarium', 'Staff recognition event supplies',
    'Graduation ceremony materials', 'Early childhood manipulatives', 'Reading intervention materials',
    'ESL program resources', 'Adaptive PE equipment', 'Robotics club components',
    'Drama production costumes', 'Band instrument repair', 'Swimming pool chemicals',
    'Landscaping materials', 'Parking lot maintenance', 'Emergency preparedness kits',
    'Mileage reimbursement - November', 'Mileage reimbursement - December',
    'Conference travel reimbursement', 'Workshop registration fees',
  ];

  const lineDescriptions = [
    'Copy paper - 8.5x11 case', 'Dry erase markers (12-pack)', 'Printer toner HP 26A',
    'Student workbooks', 'Chromebook chargers', 'Glue sticks bulk', 'Scissors classroom set',
    'Beakers 250ml (set of 6)', 'Microscope slides', 'Dissection kit', 'Safety goggles',
    'Basketball - official size', 'Volleyball net', 'Track hurdles', 'Football helmets',
    'Acrylic paint set', 'Canvas 16x20 (10-pack)', 'Sketch pads', 'Watercolor palette',
    'Floor cleaner concentrate', 'Trash bags 55gal', 'Paper towels bulk', 'Hand sanitizer',
    'File folders letter size', 'Binder clips assorted', 'Sticky notes 3x3', 'Laminating pouches',
    'Picture books grade K-2', 'Chapter books grade 3-5', 'Reference encyclopedia set',
    'Trumpet student model', 'Clarinet reeds (box 25)', 'Sheet music - concert band',
    'Swing set chains', 'Sandbox cover', 'HVAC filter 20x25x1', 'Light bulbs LED T8',
    'Software license annual', 'Assessment booklets', 'Cafeteria trays (50-pack)',
  ];

  const statuses = ['draft', 'submitted', 'submitted', 'accounting-review', 'accounting-review', 'ap-review', 'approved', 'approved', 'approved', 'approved', 'rejected', 'archived'];
  const apBatches = [null, null, null, 'AP-2025-001', 'AP-2025-002', 'AP-2025-003', 'AP-2025-004', 'AP-2025-005', 'AP-2025-006', 'AP-2025-007'];

  // Helpers
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
  function randRecentDate() {
    // Generate dates from ~60 days ago to today so invoice ages are realistic
    const now = Date.now();
    const daysAgo = randInt(0, 60);
    const d = new Date(now - daysAgo * 86400000);
    return d.toISOString().split('T')[0];
  }
  function randInvoiceDate(submissionDate) {
    // Invoice date is 0-15 days before submission date
    const sub = new Date(submissionDate);
    const daysBefore = randInt(0, 15);
    const d = new Date(sub.getTime() - daysBefore * 86400000);
    return d.toISOString().split('T')[0];
  }
  function randPrice(min, max) { return (Math.random() * (max - min) + min).toFixed(2); }

  try {
    // Get current sequence value and reset to 0 for clean numbering
    await env.DB.prepare("UPDATE sequences SET value = 0 WHERE name = 'rfp_no'").run();
    let currentRfp = 0;

    // Build all statements
    const allStmts = [];

    for (let i = 0; i < COUNT; i++) {
      currentRfp++;
      const isVendor = Math.random() > 0.2;
      const isMileage = !isVendor && Math.random() > 0.5;
      const reqType = isMileage ? 'mileage' : (isVendor ? 'vendor' : 'reimbursement');
      const sub = pick(submitters);
      const vendor = isVendor ? pick(vendors) : null;
      const emp = !isVendor ? pick(employees) : null;
      const status = pick(statuses);
      const submissionDate = randRecentDate();
      const mileageTotal = isMileage ? randInt(15, 280) : 0;

      allStmts.push(
        env.DB.prepare(`
          INSERT INTO dashboard_data (
            rfp_number, submitter_name, submitter_id, budget_approver,
            submission_date, request_type, vendor_name, vendor_number,
            vendor_address, invoice_number, employee_name, employee_id,
            description, status, assigned_to, ap_batch, mileage_total, creation_source, check_number
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          currentRfp,
          sub.name,
          sub.id,
          pick(approvers),
          submissionDate,
          reqType,
          vendor ? vendor.name : null,
          vendor ? vendor.number : null,
          vendor ? vendor.address : null,
          isVendor ? `INV-${randInt(10000, 99999)}` : null,
          emp ? emp.name : null,
          emp ? emp.id : null,
          pick(descriptions),
          status,
          pick(approvers),
          (status === 'approved' || status === 'ap-review' || status === 'archived') ? pick(apBatches) : null,
          mileageTotal,
          pick(['manual', 'manual', 'manual', 'import', 'capture']),
          (status === 'approved' && Math.random() > 0.4) ? String(randInt(100000, 999999)) : null,
        )
      );

      // Add 1-4 line items per RFP
      const lineCount = isMileage ? randInt(2, 6) : randInt(1, 4);
      const bc = pick(budgetCodes);
      const ac = pick(accountCodes);
      const fund = bc.substring(0, 2);
      const org = bc.substring(2, 5);
      const prog = bc.substring(5, 8);
      const fin = bc.substring(8, 11);

      for (let ln = 1; ln <= lineCount; ln++) {
        const qty = randInt(1, 25);
        const unitPrice = parseFloat(randPrice(5, 450));
        const total = parseFloat((qty * unitPrice).toFixed(2));

        allStmts.push(
          env.DB.prepare(`
            INSERT INTO form_data (
              rfp_number, line_number, description, fund, organization,
              program, finance, object, quantity, unit_price, total,
              invoice_number, invoice_date, budget_code, account_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            currentRfp,
            ln,
            pick(lineDescriptions),
            fund,
            org,
            prog,
            fin,
            ac,
            qty,
            unitPrice,
            total,
            isVendor ? `INV-${randInt(10000, 99999)}` : null,
            randInvoiceDate(submissionDate),
            bc,
            ac,
          )
        );
      }
    }

    // D1 batch limit is ~500, so chunk
    const BATCH_SIZE = 400;
    for (let i = 0; i < allStmts.length; i += BATCH_SIZE) {
      await env.DB.batch(allStmts.slice(i, i + BATCH_SIZE));
    }

    // Update sequence
    await env.DB.prepare("UPDATE sequences SET value = ? WHERE name = 'rfp_no'")
      .bind(currentRfp).run();

    return json({ message: `Seeded ${COUNT} RFPs (rfp_number ${currentRfp - COUNT + 1} to ${currentRfp}), ~${allStmts.length} total rows.` });
  } catch (e) {
    return json({ error: e.message, stack: e.stack }, 500);
  }
}


async function handleMigrate(env) {
  const migrations = [
    'ALTER TABLE form_data ADD COLUMN invoice_number TEXT',
    'ALTER TABLE form_data ADD COLUMN invoice_date TEXT',
    'ALTER TABLE form_data ADD COLUMN budget_code TEXT',
    'ALTER TABLE form_data ADD COLUMN account_code TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN creation_source TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN deleted_at TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN check_number TEXT',
    'ALTER TABLE user_data ADD COLUMN dashboard_prefs TEXT',
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rfp_number INTEGER NOT NULL,
      action TEXT NOT NULL,
      description TEXT,
      performed_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (rfp_number) REFERENCES dashboard_data(rfp_number)
    )`,
    `CREATE TABLE IF NOT EXISTS mileage_trips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rfp_number INTEGER NOT NULL,
      trip_number INTEGER NOT NULL,
      trip_date TEXT,
      from_location TEXT,
      to_location TEXT,
      miles REAL DEFAULT 0,
      rate REAL DEFAULT 0,
      amount REAL DEFAULT 0,
      budget_code TEXT,
      account_code TEXT,
      FOREIGN KEY (rfp_number) REFERENCES dashboard_data(rfp_number)
    )`,
    `CREATE TABLE IF NOT EXISTS sequences (
      name TEXT PRIMARY KEY,
      value INTEGER NOT NULL DEFAULT 0
    )`,
  ];

  const results = [];
  for (const sql of migrations) {
    try {
      await env.DB.prepare(sql).run();
      results.push({ sql: sql.substring(0, 60), status: 'applied' });
    } catch (e) {
      results.push({ sql: sql.substring(0, 60), status: 'skipped', reason: e.message });
    }
  }

  // Seed rfp_no sequence from current max if not yet set
  try {
    const { results: existing } = await env.DB.prepare(
      "SELECT value FROM sequences WHERE name = 'rfp_no'"
    ).all();

    if (!existing.length) {
      const { results: maxRow } = await env.DB.prepare(
        'SELECT MAX(rfp_number) as max_num FROM dashboard_data'
      ).all();
      const seed = maxRow[0]?.max_num || 2600000;
      await env.DB.prepare(
        "INSERT INTO sequences (name, value) VALUES ('rfp_no', ?)"
      ).bind(seed).run();
      results.push({ sql: 'SEED sequences.rfp_no', status: 'applied', value: seed });
    } else {
      results.push({ sql: 'SEED sequences.rfp_no', status: 'skipped', reason: `already set to ${existing[0].value}` });
    }
  } catch (e) {
    results.push({ sql: 'SEED sequences.rfp_no', status: 'error', reason: e.message });
  }

  return json({ message: 'Migration complete', results });
}

// Re-parse all budget_code strings and update fund/org/program/finance/course columns
async function handleMigrateBudgetComponents(env) {
  const { results: rows } = await env.DB.prepare(
    'SELECT rowid, budget_code FROM budget_code WHERE budget_code IS NOT NULL'
  ).all();

  let updated = 0, skipped = 0;
  const batches = [];
  let batch = [];

  for (const row of rows) {
    const c = (row.budget_code || '').toString().replace(/[^0-9]/g, '');
    if (c.length < 14) { skipped++; continue; }

    const fund = c.substring(0, 2);
    const org = c.substring(2, 5);
    const program = c.substring(5, 8);
    const finance = c.substring(8, 11);
    const course = c.substring(11, 14);

    batch.push(
      env.DB.prepare(
        'UPDATE budget_code SET fund = ?, organization = ?, program = ?, finance = ?, course = ? WHERE rowid = ?'
      ).bind(fund, org, program, finance, course, row.rowid)
    );

    if (batch.length >= 400) {
      batches.push(batch);
      batch = [];
    }
    updated++;
  }
  if (batch.length) batches.push(batch);

  for (const b of batches) {
    await env.DB.batch(b);
  }

  return json({ message: `Re-parsed budget code components (2+3+3+3+3 format)`, updated, skipped, total: rows.length });
}


/* ========================================
   AUDIT LOGS
   ======================================== */
async function handleGetAuditLogs(rfpNumber, env) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY created_at ASC, id ASC'
    ).bind(rfpNumber).all();
    return json({ auditLogs: results });
  } catch (e) {
    return json({ auditLogs: [] });
  }
}

async function handleCreateAuditLog(rfpNumber, request, env) {
  const body = await request.json();
  try {
    await env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, created_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(
      rfpNumber,
      body.action || 'update',
      body.description || '',
      body.performed_by || 'Unknown',
      new Date().toISOString(),
    ).run();
    return json({ message: 'Audit log created' }, 201);
  } catch (e) {
    return json({ error: 'Failed to create audit log', detail: e.message }, 500);
  }
}


/* ========================================
   ATTACHMENTS – LIST
   ======================================== */
async function handleListAttachments(rfpNumber, env) {
  if (!env.BUCKET) {
    return json({ error: 'R2 bucket not configured', attachments: [], count: 0 }, 500);
  }

  const prefix = `rfp/${rfpNumber}/`;
  const listed = await env.BUCKET.list({ prefix });

  const files = listed.objects.map(obj => ({
    key: obj.key,
    name: obj.customMetadata?.originalName || obj.key.split('/').pop(),
    size: obj.size,
    contentType: obj.httpMetadata?.contentType || 'application/octet-stream',
    uploaded: obj.uploaded?.toISOString() || null,
    uploadedBy: obj.customMetadata?.uploadedBy || null,
  }));

  return json({ attachments: files, count: files.length });
}


/* ========================================
   ATTACHMENTS – UPLOAD
   ======================================== */
async function handleUploadAttachment(rfpNumber, request, env) {
  if (!env.BUCKET) {
    return json({ error: 'R2 bucket not configured. Check wrangler.toml BUCKET binding.' }, 500);
  }

  const contentType = request.headers.get('Content-Type') || '';

  if (contentType.includes('multipart/form-data')) {
    let formData;
    try {
      formData = await request.formData();
    } catch (e) {
      return json({ error: 'Failed to parse form data', detail: e.message }, 400);
    }

    const results = [];

    for (const [fieldName, file] of formData.entries()) {
      if (typeof file === 'string') continue; // skip non-file entries

      const safeName = (file.name || 'unnamed').replace(/[^a-zA-Z0-9._-]/g, '_');
      const timestamp = Date.now();
      const key = `rfp/${rfpNumber}/${timestamp}_${safeName}`;

      try {
        await env.BUCKET.put(key, file.stream(), {
          httpMetadata: { contentType: file.type || 'application/octet-stream' },
          customMetadata: {
            originalName: file.name || 'unnamed',
            rfpNumber: String(rfpNumber),
            uploadedBy: request.headers.get('Cf-Access-Authenticated-User-Email') || 'unknown',
            uploadedAt: new Date().toISOString(),
          },
        });
      } catch (e) {
        return json({ error: 'R2 put failed', detail: e.message, key }, 500);
      }

      results.push({
        key,
        name: file.name || 'unnamed',
        size: file.size,
        contentType: file.type,
      });
    }

    return json({ uploaded: results, count: results.length }, 201);
  }

  // Single file upload via raw body
  const fileName = request.headers.get('X-File-Name') || 'attachment';
  const fileType = request.headers.get('X-Content-Type') || contentType || 'application/octet-stream';
  const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const timestamp = Date.now();
  const key = `rfp/${rfpNumber}/${timestamp}_${safeName}`;

  await env.BUCKET.put(key, request.body, {
    httpMetadata: { contentType: fileType },
    customMetadata: {
      originalName: fileName,
      rfpNumber: String(rfpNumber),
      uploadedBy: request.headers.get('Cf-Access-Authenticated-User-Email') || 'unknown',
      uploadedAt: new Date().toISOString(),
    },
  });

  return json({ key, name: fileName, contentType: fileType }, 201);
}


/* ========================================
   ATTACHMENTS – DOWNLOAD
   ======================================== */
async function handleDownloadAttachment(key, env) {
  const object = await env.BUCKET.get(key);
  if (!object) {
    return json({ error: 'Attachment not found' }, 404);
  }

  const originalName = object.customMetadata?.originalName || key.split('/').pop();
  const contentType = object.httpMetadata?.contentType || 'application/octet-stream';

  // For PDFs and images, allow inline viewing; otherwise force download
  const isViewable = contentType.startsWith('image/') || contentType === 'application/pdf';
  const disposition = isViewable
    ? `inline; filename="${originalName}"`
    : `attachment; filename="${originalName}"`;

  return new Response(object.body, {
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': disposition,
      'Content-Length': object.size,
      ...CORS_HEADERS,
    },
  });
}


/* ========================================
   ATTACHMENTS – DELETE
   ======================================== */
async function handleDeleteAttachment(key, env) {
  await env.BUCKET.delete(key);
  return json({ message: 'Attachment deleted', key });
}


/* ========================================
   USER MANAGEMENT – LIST
   ======================================== */
async function handleGetUsers(env) {
  const { results: users } = await env.DB.prepare(
    'SELECT user_id, user_first_name, user_last_name, user_email, phone_number, department, title, profile_picture_key, status FROM user_data ORDER BY user_first_name ASC'
  ).all();

  let allRoles = [];
  try {
    const { results: roleResults } = await env.DB.prepare(
      'SELECT user_email, role FROM user_roles ORDER BY user_email, role'
    ).all();
    allRoles = roleResults;
  } catch (e) { /* user_roles table may not exist yet */ }

  const roleMap = {};
  for (const r of allRoles) {
    const email = r.user_email.toLowerCase();
    if (!roleMap[email]) roleMap[email] = [];
    roleMap[email].push(r.role);
  }

  const merged = users.map(u => ({
    user_id: u.user_id,
    first_name: u.user_first_name,
    last_name: u.user_last_name,
    email: u.user_email,
    phone_number: u.phone_number || '',
    department: u.department || '',
    title: u.title || '',
    profile_picture_key: u.profile_picture_key || null,
    status: u.status || 'active',
    roles: roleMap[u.user_email.toLowerCase()] || [],
  }));

  return json({ users: merged, total: merged.length });
}


/* ========================================
   USER MANAGEMENT – UPDATE STATUS
   ======================================== */
async function handleUpdateUserStatus(request, env) {
  const body = await request.json();
  const { email, status } = body;

  if (!email || !status) return json({ error: 'email and status are required' }, 400);
  if (!['active', 'inactive'].includes(status)) return json({ error: 'status must be active or inactive' }, 400);

  try {
    await env.DB.prepare(
      'UPDATE user_data SET status = ? WHERE LOWER(user_email) = ?'
    ).bind(status, email.toLowerCase().trim()).run();
    return json({ message: 'Status updated', email, status });
  } catch (e) {
    return json({ error: 'Failed to update status: ' + e.message }, 500);
  }
}


/* ========================================
   PROFILE – UPDATE
   ======================================== */
async function handleUpdateProfile(request, env) {
  const body = await request.json();
  const { email, phone_number, department, title } = body;

  if (!email) return json({ error: 'email is required' }, 400);

  try {
    await env.DB.prepare(
      'UPDATE user_data SET phone_number = ?, department = ?, title = ? WHERE LOWER(user_email) = ?'
    ).bind(phone_number || '', department || '', title || '', email.toLowerCase().trim()).run();
    return json({ message: 'Profile updated' });
  } catch (e) {
    return json({ error: 'Failed to update profile: ' + e.message }, 500);
  }
}


/* ========================================
   PROFILE PICTURE – GET
   ======================================== */
async function handleGetProfilePicture(email, env) {
  if (!env.BUCKET) return json({ error: 'R2 bucket not configured' }, 500);

  // Look up the user's profile_picture_key
  const { results } = await env.DB.prepare(
    'SELECT profile_picture_key FROM user_data WHERE LOWER(user_email) = ?'
  ).bind(email.toLowerCase().trim()).all();

  const key = results[0]?.profile_picture_key;
  if (!key) return json({ error: 'No profile picture' }, 404);

  const object = await env.BUCKET.get(key);
  if (!object) return json({ error: 'Picture not found in storage' }, 404);

  const contentType = object.httpMetadata?.contentType || 'image/jpeg';
  return new Response(object.body, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=3600',
      ...CORS_HEADERS,
    },
  });
}


/* ========================================
   PROFILE PICTURE – UPLOAD
   ======================================== */
async function handleUploadProfilePicture(request, env) {
  if (!env.BUCKET) return json({ error: 'R2 bucket not configured' }, 500);

  const formData = await request.formData();
  const file = formData.get('file');
  const email = formData.get('email');

  if (!file || !email) return json({ error: 'file and email are required' }, 400);

  const ext = (file.name || 'photo.jpg').split('.').pop().toLowerCase();
  const key = `profile-pictures/${email.toLowerCase().trim()}.${ext}`;

  await env.BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type || 'image/jpeg' },
    customMetadata: { email: email.toLowerCase().trim(), uploadedAt: new Date().toISOString() },
  });

  // Update user_data with the key
  await env.DB.prepare(
    'UPDATE user_data SET profile_picture_key = ? WHERE LOWER(user_email) = ?'
  ).bind(key, email.toLowerCase().trim()).run();

  return json({ message: 'Profile picture uploaded', key });
}


/* ========================================
   MILEAGE – SITES LIST
   ======================================== */
async function handleMileageSites(env) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT DISTINCT from_site AS site FROM mileage_table UNION SELECT DISTINCT to_site AS site FROM mileage_table ORDER BY site'
    ).all();
    return json({ sites: results.map(r => r.site) });
  } catch (e) {
    return json({ error: 'Failed to load sites', detail: e.message }, 500);
  }
}


/* ========================================
   MILEAGE – DISTRICT DISTANCE LOOKUP
   ======================================== */
async function handleMileageDistance(env, url) {
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');

  if (!from || !to) return json({ error: 'Missing from/to params' }, 400);

  const { results } = await env.DB.prepare(
    'SELECT distance FROM mileage_table WHERE from_site = ? AND to_site = ?'
  ).bind(from, to).all();

  if (results.length > 0) {
    return json({ from, to, distance: results[0].distance, source: 'district' });
  }

  // Try reverse
  const { results: rev } = await env.DB.prepare(
    'SELECT distance FROM mileage_table WHERE from_site = ? AND to_site = ?'
  ).bind(to, from).all();

  if (rev.length > 0) {
    return json({ from, to, distance: rev[0].distance, source: 'district' });
  }

  return json({ error: 'Route not found', from, to }, 404);
}


/* ========================================
   MILEAGE – GOOGLE MAPS CALCULATE
   ======================================== */
async function handleMileageCalculate(request, env) {
  const body = await request.json();
  const fromAddr = body.from;
  const toAddr = body.to;

  if (!fromAddr || !toAddr) {
    return json({ error: 'Missing from/to addresses' }, 400);
  }

  const apiKey = env.GOOGLE_MAPS_API_KEY;
  if (!apiKey) {
    return json({ error: 'Google Maps API key not configured' }, 500);
  }

  try {
    const dmUrl = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${encodeURIComponent(fromAddr)}&destinations=${encodeURIComponent(toAddr)}&units=imperial&key=${apiKey}`;

    const resp = await fetch(dmUrl);
    const data = await resp.json();

    if (data.status !== 'OK') {
      return json({ error: 'Google API error', detail: data.status, errorMessage: data.error_message || null }, 502);
    }

    const element = data.rows?.[0]?.elements?.[0];
    if (!element || element.status !== 'OK') {
      return json({ error: 'No route found', detail: element?.status || 'unknown' }, 404);
    }

    // distance.value is in meters, convert to miles
    const meters = element.distance.value;
    const miles = meters / 1609.344;

    return json({
      from: fromAddr,
      to: toAddr,
      distance: Math.round(miles * 10) / 10,
      distanceText: element.distance.text,
      durationText: element.duration.text,
      source: 'google',
    });
  } catch (e) {
    return json({ error: 'Failed to calculate distance', detail: e.message }, 500);
  }
}


/* ========================================
   INVOICE EXTRACTION (Gemini Flash)
   ======================================== */
async function handleExtractInvoice(request, env) {
  if (!env.GEMINI_API_KEY) {
    return json({ error: 'GEMINI_API_KEY not configured' }, 500);
  }

  const body = await request.json();
  const { pdfBase64, fileName } = body;

  if (!pdfBase64) {
    return json({ error: 'Missing pdfBase64' }, 400);
  }

  const prompt = `You are a highly accurate invoice data extraction system. Your job is to analyze this PDF and extract every piece of financial data.

CRITICAL INSTRUCTIONS:
1. Look at EVERY page of the document carefully
2. Find ALL line items, charges, fees, or amounts listed
3. Find the vendor/company name (the entity ISSUING the invoice, not the recipient)
4. Find the invoice number and date
5. Find the invoice total

Return this exact JSON structure:
{
  "lineItems": [
    {
      "description": "ITEM DESCRIPTION IN UPPERCASE",
      "invoiceNumber": "INV-12345",
      "invoiceDate": "01/15/2026",
      "amount": 123.45
    }
  ],
  "vendorName": "VENDOR NAME IN UPPERCASE",
  "vendorNumber": "",
  "invoiceTotal": 123.45,
  "confidence": "high"
}

RULES:
- Extract ALL line items. Every charge, fee, product, or service listed should be a separate line item.
- ALL descriptions and vendor names must be UPPERCASE
- Dates must be MM/DD/YYYY format
- Amounts must be plain numbers (no $ signs, no commas). Example: 1234.56
- If there is a single total but no itemized lines, create ONE line item with the full description and total amount
- The invoiceNumber should be the same for all line items from the same invoice
- The invoiceDate should be the invoice date (not due date, not ship date)
- invoiceTotal is the document's stated grand total
- confidence should be "high" if you found clear line items, "medium" if you had to interpret, "low" if the document doesn't appear to be an invoice
- NEVER return an empty lineItems array if there are ANY amounts visible in the document
- If you see a table with items and amounts, extract EVERY row`;

  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${env.GEMINI_API_KEY}`;

  const geminiBody = {
    contents: [{
      parts: [
        {
          inlineData: {
            mimeType: 'application/pdf',
            data: pdfBase64,
          }
        },
        { text: prompt }
      ]
    }],
    generationConfig: {
      temperature: 0.0,
      maxOutputTokens: 8192,
      responseMimeType: 'application/json',
    }
  };

  // Retry up to 3 times on failure or empty results
  const MAX_RETRIES = 3;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      console.log(`[EXTRACT] Attempt ${attempt}/${MAX_RETRIES} for ${fileName || 'unknown'}`);

      const resp = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(geminiBody),
      });

      if (!resp.ok) {
        const errText = await resp.text();
        console.error(`[EXTRACT] Gemini API error (attempt ${attempt}):`, resp.status, errText);
        if (attempt === MAX_RETRIES) {
          return json({ error: 'Gemini API error', status: resp.status, detail: errText }, 502);
        }
        await new Promise(r => setTimeout(r, 1000 * attempt));
        continue;
      }

      const geminiData = await resp.json();

      // Check for blocked or empty responses
      const candidate = geminiData.candidates?.[0];
      if (!candidate || candidate.finishReason === 'SAFETY' || candidate.finishReason === 'RECITATION') {
        console.warn(`[EXTRACT] Blocked response (attempt ${attempt}): ${candidate?.finishReason}`);
        if (attempt === MAX_RETRIES) {
          return json({ error: 'Content blocked by Gemini', reason: candidate?.finishReason }, 422);
        }
        await new Promise(r => setTimeout(r, 1000 * attempt));
        continue;
      }

      const rawText = candidate.content?.parts?.[0]?.text || '';
      if (!rawText.trim()) {
        console.warn(`[EXTRACT] Empty response (attempt ${attempt})`);
        if (attempt === MAX_RETRIES) {
          return json({ error: 'Empty response from Gemini' }, 422);
        }
        await new Promise(r => setTimeout(r, 1000 * attempt));
        continue;
      }

      // Clean any markdown fences
      const cleaned = rawText.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();

      let extracted;
      try {
        extracted = JSON.parse(cleaned);
      } catch (parseErr) {
        console.error(`[EXTRACT] JSON parse failed (attempt ${attempt}):`, parseErr.message, rawText.substring(0, 200));
        if (attempt === MAX_RETRIES) {
          return json({ error: 'Failed to parse Gemini response', raw: rawText.substring(0, 500) }, 422);
        }
        await new Promise(r => setTimeout(r, 1000 * attempt));
        continue;
      }

      // If we got an empty result, retry
      if ((!extracted.lineItems || extracted.lineItems.length === 0) && attempt < MAX_RETRIES) {
        console.warn(`[EXTRACT] Empty lineItems (attempt ${attempt}), retrying...`);
        await new Promise(r => setTimeout(r, 1000 * attempt));
        continue;
      }

      console.log(`[EXTRACT] Success on attempt ${attempt}: ${extracted.lineItems?.length || 0} line items`);

      return json({
        success: true,
        fileName: fileName || 'unknown',
        attempt,
        ...extracted,
      });

    } catch (e) {
      console.error(`[EXTRACT] Error (attempt ${attempt}):`, e.message);
      if (attempt === MAX_RETRIES) {
        return json({ error: 'Extraction failed', detail: e.message }, 500);
      }
      await new Promise(r => setTimeout(r, 1000 * attempt));
    }
  }

  return json({ error: 'Extraction failed after all retries' }, 500);
}
