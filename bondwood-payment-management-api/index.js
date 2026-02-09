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
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
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

      // ── Vendors ──
      if (path === '/api/vendors' && method === 'GET') {
        return handleGetVendors(env, url);
      }

      // ── Budget Codes ──
      if (path === '/api/budget-codes' && method === 'GET') {
        return handleGetBudgetCodes(env, url);
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
      if (path === '/api/rfps/search' && method === 'POST') {
        return handleAdvancedSearch(request, env);
      }
      if (path === '/api/rfps/search-options' && method === 'GET') {
        return handleSearchOptions(env);
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

      // ── Audit Logs ──
      const auditMatch = path.match(/^\/api\/rfps\/(\d+)\/audit-log$/);
      if (auditMatch) {
        const rfpNumber = parseInt(auditMatch[1]);
        if (method === 'GET') return handleGetAuditLog(rfpNumber, env);
        if (method === 'POST') return handleAddAuditLog(rfpNumber, request, env);
      }

      const attItemMatch = path.match(/^\/api\/attachments\/(.+)$/);
      if (attItemMatch) {
        const key = decodeURIComponent(attItemMatch[1]);
        if (method === 'GET') return handleDownloadAttachment(key, env);
        if (method === 'DELETE') return handleDeleteAttachment(key, env);
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

      // ── Migrate ──
      if (path === '/api/migrate' && method === 'POST') {
        return handleMigrate(env);
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
    'SELECT user_id, user_first_name, user_last_name, user_email FROM user_data WHERE LOWER(user_email) = ?'
  ).bind(email.toLowerCase().trim()).all();

  if (!results.length) {
    return json({ error: 'User not found' }, 404);
  }

  const u = results[0];
  return json({
    user_id: u.user_id,
    first_name: u.user_first_name,
    last_name: u.user_last_name,
    email: u.user_email,
  });
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

  let where = [];
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

  // Get RFPs with line item totals
  const { results } = await env.DB.prepare(`
    SELECT d.*, COALESCE(SUM(f.total), 0) as total_amount,
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
   RFPs – SEARCH OPTIONS (distinct values)
   ======================================== */
async function handleSearchOptions(env) {
  try {
    const [
      statusR, typeR, submitterR, assignedR, batchR,
      vendorNameR, vendorNumR,
      descR, invNumR,
      budgetCodeR, acctCodeR, fundR, orgR, progR, finR, courseR
    ] = await env.DB.batch([
      env.DB.prepare("SELECT DISTINCT status FROM dashboard_data WHERE status IS NOT NULL AND status != '' ORDER BY status"),
      env.DB.prepare("SELECT DISTINCT request_type FROM dashboard_data WHERE request_type IS NOT NULL AND request_type != '' ORDER BY request_type"),
      env.DB.prepare("SELECT DISTINCT submitter_name FROM dashboard_data WHERE submitter_name IS NOT NULL AND submitter_name != '' ORDER BY submitter_name"),
      env.DB.prepare("SELECT DISTINCT assigned_to FROM dashboard_data WHERE assigned_to IS NOT NULL AND assigned_to != '' ORDER BY assigned_to"),
      env.DB.prepare("SELECT DISTINCT ap_batch FROM dashboard_data WHERE ap_batch IS NOT NULL AND ap_batch != '' ORDER BY ap_batch"),
      env.DB.prepare("SELECT DISTINCT vendor_name FROM dashboard_data WHERE vendor_name IS NOT NULL AND vendor_name != '' ORDER BY vendor_name"),
      env.DB.prepare("SELECT DISTINCT vendor_number FROM dashboard_data WHERE vendor_number IS NOT NULL AND vendor_number != '' ORDER BY vendor_number"),
      env.DB.prepare("SELECT DISTINCT description FROM form_data WHERE description IS NOT NULL AND description != '' ORDER BY description"),
      env.DB.prepare("SELECT DISTINCT invoice_number FROM form_data WHERE invoice_number IS NOT NULL AND invoice_number != '' ORDER BY invoice_number"),
      env.DB.prepare("SELECT DISTINCT budget_code FROM form_data WHERE budget_code IS NOT NULL AND budget_code != '' ORDER BY budget_code"),
      env.DB.prepare("SELECT DISTINCT COALESCE(account_code, object) as account_code FROM form_data WHERE (account_code IS NOT NULL AND account_code != '') OR (object IS NOT NULL AND object != '') ORDER BY 1"),
      env.DB.prepare("SELECT DISTINCT fund FROM form_data WHERE fund IS NOT NULL AND fund != '' ORDER BY fund"),
      env.DB.prepare("SELECT DISTINCT organization FROM form_data WHERE organization IS NOT NULL AND organization != '' ORDER BY organization"),
      env.DB.prepare("SELECT DISTINCT program FROM form_data WHERE program IS NOT NULL AND program != '' ORDER BY program"),
      env.DB.prepare("SELECT DISTINCT finance FROM form_data WHERE finance IS NOT NULL AND finance != '' ORDER BY finance"),
      env.DB.prepare("SELECT DISTINCT course FROM form_data WHERE course IS NOT NULL AND course != '' ORDER BY course"),
    ]);

    const pluck = (res, col) => res.results.map(r => r[col]).filter(Boolean);

    return json({
      status: pluck(statusR, 'status'),
      request_type: pluck(typeR, 'request_type'),
      submitter_name: pluck(submitterR, 'submitter_name'),
      assigned_to: pluck(assignedR, 'assigned_to'),
      ap_batch: pluck(batchR, 'ap_batch'),
      vendor_name: pluck(vendorNameR, 'vendor_name'),
      vendor_number: pluck(vendorNumR, 'vendor_number'),
      description: pluck(descR, 'description'),
      invoice_number: pluck(invNumR, 'invoice_number'),
      budget_code: pluck(budgetCodeR, 'budget_code'),
      account_code: pluck(acctCodeR, 'account_code'),
      fund: pluck(fundR, 'fund'),
      organization: pluck(orgR, 'organization'),
      program: pluck(progR, 'program'),
      finance: pluck(finR, 'finance'),
      course: pluck(courseR, 'course'),
    });
  } catch (e) {
    return json({ error: 'Failed to fetch search options', detail: e.message }, 500);
  }
}


/* ========================================
   RFPs – ADVANCED SEARCH
   ======================================== */
async function handleAdvancedSearch(request, env) {
  const body = await request.json();
  let where = [];
  let params = [];
  let needsJoin = false;

  // Helper: build OR clause for multi-value fields
  // values can be a string or array; uses LIKE for partial matching
  function addLikeOr(column, values, join) {
    const arr = Array.isArray(values) ? values : [values];
    const filtered = arr.map(v => String(v).trim()).filter(Boolean);
    if (!filtered.length) return;
    if (join) needsJoin = true;
    if (filtered.length === 1) {
      where.push(`${column} LIKE ?`);
      params.push(`%${filtered[0]}%`);
    } else {
      const clauses = filtered.map(() => `${column} LIKE ?`);
      where.push(`(${clauses.join(' OR ')})`);
      filtered.forEach(v => params.push(`%${v}%`));
    }
  }

  // Helper: exact match OR for multi-value fields
  function addExactOr(column, values, join) {
    const arr = Array.isArray(values) ? values : [values];
    const filtered = arr.map(v => String(v).trim()).filter(Boolean);
    if (!filtered.length) return;
    if (join) needsJoin = true;
    if (filtered.length === 1) {
      where.push(`${column} = ?`);
      params.push(filtered[0]);
    } else {
      where.push(`${column} IN (${filtered.map(() => '?').join(',')})`);
      filtered.forEach(v => params.push(v));
    }
  }

  // Dashboard fields
  if (body.rfp_number) addLikeOr('CAST(d.rfp_number AS TEXT)', body.rfp_number, false);
  if (body.status) addExactOr('d.status', body.status, false);
  if (body.request_type) {
    where.push('d.request_type = ?');
    params.push(body.request_type);
  }
  if (body.submitter_name) addLikeOr('d.submitter_name', body.submitter_name, false);
  if (body.assigned_to) addLikeOr('d.assigned_to', body.assigned_to, false);
  if (body.ap_batch) addLikeOr('d.ap_batch', body.ap_batch, false);
  if (body.vendor_name) addLikeOr('d.vendor_name', body.vendor_name, false);
  if (body.vendor_number) addLikeOr('d.vendor_number', body.vendor_number, false);
  if (body.date_from) {
    where.push('d.submission_date >= ?');
    params.push(body.date_from);
  }
  if (body.date_to) {
    where.push('d.submission_date <= ?');
    params.push(body.date_to);
  }

  // Form data fields
  if (body.description) addLikeOr('f.description', body.description, true);
  if (body.invoice_number) addLikeOr('f.invoice_number', body.invoice_number, true);
  if (body.inv_date_from) {
    needsJoin = true;
    where.push('f.invoice_date >= ?');
    params.push(body.inv_date_from);
  }
  if (body.inv_date_to) {
    needsJoin = true;
    where.push('f.invoice_date <= ?');
    params.push(body.inv_date_to);
  }
  if (body.budget_code) addLikeOr('f.budget_code', body.budget_code, true);

  // Account code — check both account_code and object columns
  if (body.account_code) {
    const arr = Array.isArray(body.account_code) ? body.account_code : [body.account_code];
    const filtered = arr.map(v => String(v).trim()).filter(Boolean);
    if (filtered.length) {
      needsJoin = true;
      const clauses = filtered.map(() => `(f.account_code LIKE ? OR f.object LIKE ?)`);
      where.push(`(${clauses.join(' OR ')})`);
      filtered.forEach(v => { params.push(`%${v}%`); params.push(`%${v}%`); });
    }
  }

  if (body.fund) addLikeOr('f.fund', body.fund, true);
  if (body.organization) addLikeOr('f.organization', body.organization, true);
  if (body.program) addLikeOr('f.program', body.program, true);
  if (body.finance) addLikeOr('f.finance', body.finance, true);
  if (body.course) addLikeOr('f.course', body.course, true);
  if (body.amount_min != null && !isNaN(body.amount_min)) {
    needsJoin = true;
    where.push('f.total >= ?');
    params.push(body.amount_min);
  }
  if (body.amount_max != null && !isNaN(body.amount_max)) {
    needsJoin = true;
    where.push('f.total <= ?');
    params.push(body.amount_max);
  }

  if (where.length === 0) {
    return json({ rfp_numbers: [], message: 'No criteria provided' }, 400);
  }

  const joinClause = needsJoin ? 'INNER JOIN form_data f ON d.rfp_number = f.rfp_number' : '';
  const whereClause = 'WHERE ' + where.join(' AND ');

  const sql = `SELECT DISTINCT d.rfp_number FROM dashboard_data d ${joinClause} ${whereClause} ORDER BY d.rfp_number DESC`;
  console.log('[ADV SEARCH] SQL:', sql);
  console.log('[ADV SEARCH] Params:', params);

  try {
    const { results } = await env.DB.prepare(sql).bind(...params).all();
    const rfpNumbers = results.map(r => r.rfp_number);
    return json({ rfp_numbers: rfpNumbers, total: rfpNumbers.length });
  } catch (e) {
    return json({ error: 'Search query failed', detail: e.message }, 500);
  }
}


/* ========================================
   RFPs – GET SINGLE
   ======================================== */
async function handleGetRFP(rfpNumber, env) {
  // Run all queries in parallel using D1 batch
  const [headerResult, rowsResult, auditResult] = await env.DB.batch([
    env.DB.prepare('SELECT * FROM dashboard_data WHERE rfp_number = ?').bind(rfpNumber),
    env.DB.prepare('SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number').bind(rfpNumber),
    env.DB.prepare('SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY performed_at ASC, id ASC').bind(rfpNumber),
  ]);

  const header = headerResult.results;
  if (!header.length) {
    return json({ error: 'RFP not found' }, 404);
  }

  // Split into line items vs mileage trips
  const lineItems = [];
  const mileageTrips = [];
  for (const row of rowsResult.results) {
    if (row.description === 'BUSINESS MILEAGE') {
      mileageTrips.push({
        trip_number: row.line_number,
        trip_date: row.invoice_date,
        from_location: row.mileage_from,
        to_location: row.mileage_to,
        miles: row.quantity,
        rate: row.unit_price,
        amount: row.total,
        budget_code: row.budget_code,
        account_code: row.account_code,
      });
    } else {
      lineItems.push(row);
    }
  }

  const auditLogs = auditResult.results || [];

  return json({ ...header[0], lineItems, mileageTrips, auditLogs });
}


/* ========================================
   RFPs – CREATE
   ======================================== */
async function handleCreateRFP(request, env) {
  const body = await request.json();

  // Generate next RFP number
  const { results: maxRow } = await env.DB.prepare(
    'SELECT MAX(rfp_number) as max_num FROM dashboard_data'
  ).all();
  const nextRfp = (maxRow[0]?.max_num || 2600000) + 1;

  const status = body.status || 'draft';
  const submissionDate = body.submission_date || new Date().toISOString().split('T')[0];

  const headerStmt = env.DB.prepare(`
    INSERT INTO dashboard_data (
      rfp_number, submitter_name, submitter_id, budget_approver,
      submission_date, request_type, vendor_name, vendor_number,
      vendor_address, invoice_number, employee_name, employee_id,
      description, status, assigned_to, ap_batch, mileage_total
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
  ];

  const statements = [headerStmt.bind(...headerParams)];

  // Helper: parse budget code into components
  // Fund=digits 1-2, Org=3-5, Program=6-8, Finance=9-11, Course=12-14
  function parseBudgetCode(bc) {
    const s = (bc || '').replace(/\D/g, '');
    return {
      fund: s.substring(0, 2) || null,
      organization: s.substring(2, 5) || null,
      program: s.substring(5, 8) || null,
      finance: s.substring(8, 11) || null,
      course: s.substring(11, 14) || null,
    };
  }

  const submissionType = body.request_type === 'reimbursement' ? 'employee_reimbursement' : 'vendor_payment';
  let lineNum = 0;

  if (body.lineItems && body.lineItems.length) {
    for (const item of body.lineItems) {
      lineNum++;
      const bc = parseBudgetCode(item.budget_code);
      statements.push(
        env.DB.prepare(`
          INSERT INTO form_data (
            rfp_number, submission_type, line_number, description, fund, organization,
            program, finance, object, course, quantity, unit_price, total,
            invoice_number, invoice_date, budget_code, account_code,
            mileage_from, mileage_to
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          nextRfp,
          submissionType,
          lineNum,
          item.description || '',
          bc.fund,
          bc.organization,
          bc.program,
          bc.finance,
          item.account_code || null,
          bc.course,
          item.quantity || 1,
          item.unit_price || item.total || 0,
          item.total || 0,
          item.invoice_number || null,
          item.invoice_date || null,
          item.budget_code || null,
          item.account_code || null,
          null,
          null,
        )
      );
    }
  }

  // Mileage trips go into form_data as well
  if (body.mileageTrips && body.mileageTrips.length) {
    for (const trip of body.mileageTrips) {
      lineNum++;
      const bc = parseBudgetCode(trip.budget_code);
      statements.push(
        env.DB.prepare(`
          INSERT INTO form_data (
            rfp_number, submission_type, line_number, description, fund, organization,
            program, finance, object, course, quantity, unit_price, total,
            invoice_number, invoice_date, budget_code, account_code,
            mileage_from, mileage_to
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          nextRfp,
          submissionType,
          lineNum,
          'BUSINESS MILEAGE',
          bc.fund,
          bc.organization,
          bc.program,
          bc.finance,
          trip.account_code || null,
          bc.course,
          trip.miles || 0,
          trip.rate || 0,
          trip.amount || 0,
          null,
          trip.trip_date || null,
          trip.budget_code || null,
          trip.account_code || null,
          trip.from_location || null,
          trip.to_location || null,
        )
      );
    }
  }

  await env.DB.batch(statements);

  // Write audit log entry
  const submitter = (body.submitter_name && body.submitter_name.trim()) || 'Unknown User';
  const payee = body.request_type === 'vendor'
    ? (body.vendor_name || 'an unknown vendor')
    : 'Employee Reimbursement';
  let totalAmount = 0;
  if (body.lineItems) body.lineItems.forEach(i => { totalAmount += (i.total || 0); });
  if (body.mileageTrips) body.mileageTrips.forEach(t => { totalAmount += (t.amount || 0); });
  if (totalAmount === 0) totalAmount = body.mileage_total || 0;
  const amountStr = '$' + totalAmount.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');

  const auditAction = status === 'draft' ? 'created a draft' : 'submitted';
  const auditDesc = `${submitter} ${auditAction} request for payment with ${payee} for ${amountStr}`;
  try {
    await buildAuditInsert(env, nextRfp, status === 'draft' ? 'draft-created' : 'submitted', auditDesc, submitter, {
      request_type: body.request_type,
      vendor_name: body.vendor_name || null,
      employee_name: body.employee_name || null,
      total_amount: totalAmount,
      status: status,
    }).run();
  } catch (e) {
    console.error('Audit log insert failed:', e.message);
  }

  return json({ rfp_number: nextRfp, status, message: 'RFP created' }, 201);
}


/* ========================================
   RFPs – UPDATE
   ======================================== */
async function handleUpdateRFP(rfpNumber, request, env) {
  const body = await request.json();

  const { results: existing } = await env.DB.prepare(
    'SELECT id FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!existing.length) {
    return json({ error: 'RFP not found' }, 404);
  }

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

  // Helper: parse budget code into components
  function parseBudgetCode(bc) {
    const s = (bc || '').replace(/\D/g, '');
    return {
      fund: s.substring(0, 2) || null,
      organization: s.substring(2, 5) || null,
      program: s.substring(5, 8) || null,
      finance: s.substring(8, 11) || null,
      course: s.substring(11, 14) || null,
    };
  }

  const submissionType = body.request_type === 'reimbursement' ? 'employee_reimbursement'
    : body.request_type === 'vendor' ? 'vendor_payment' : null;

  // Replace line items and mileage if provided
  if (body.lineItems || body.mileageTrips) {
    statements.push(
      env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber)
    );

    let lineNum = 0;

    if (body.lineItems) {
      for (const item of body.lineItems) {
        lineNum++;
        const bc = parseBudgetCode(item.budget_code);
        statements.push(
          env.DB.prepare(`
            INSERT INTO form_data (
              rfp_number, submission_type, line_number, description, fund, organization,
              program, finance, object, course, quantity, unit_price, total,
              invoice_number, invoice_date, budget_code, account_code,
              mileage_from, mileage_to
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            rfpNumber,
            submissionType,
            lineNum,
            item.description || '',
            bc.fund,
            bc.organization,
            bc.program,
            bc.finance,
            item.account_code || null,
            bc.course,
            item.quantity || 1,
            item.unit_price || item.total || 0,
            item.total || 0,
            item.invoice_number || null,
            item.invoice_date || null,
            item.budget_code || null,
            item.account_code || null,
            null,
            null,
          )
        );
      }
    }

    if (body.mileageTrips) {
      for (const trip of body.mileageTrips) {
        lineNum++;
        const bc = parseBudgetCode(trip.budget_code);
        statements.push(
          env.DB.prepare(`
            INSERT INTO form_data (
              rfp_number, submission_type, line_number, description, fund, organization,
              program, finance, object, course, quantity, unit_price, total,
              invoice_number, invoice_date, budget_code, account_code,
              mileage_from, mileage_to
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            rfpNumber,
            submissionType,
            lineNum,
            'BUSINESS MILEAGE',
            bc.fund,
            bc.organization,
            bc.program,
            bc.finance,
            trip.account_code || null,
            bc.course,
            trip.miles || 0,
            trip.rate || 0,
            trip.amount || 0,
            null,
            trip.trip_date || null,
            trip.budget_code || null,
            trip.account_code || null,
            trip.from_location || null,
            trip.to_location || null,
          )
        );
      }
    }
  }

  if (statements.length) {
    await env.DB.batch(statements);
  }

  // Propagate ap_batch to form_data rows when provided
  if (body.ap_batch) {
    try {
      await env.DB.prepare(
        'UPDATE form_data SET ap_batch = ? WHERE rfp_number = ?'
      ).bind(body.ap_batch, rfpNumber).run();
    } catch (e) {
      console.error('Failed to update form_data ap_batch:', e.message);
    }
  }

  // Write audit log entries for notable changes
  try {
    const performer = body.performed_by || body.submitter_name || 'System';

    // Status change
    if (body.status) {
      const statusLabels = {
        'draft': 'Draft', 'submitted': 'Submitted', 'pending': 'Pending Review',
        'accounting-review': 'Accounting Review',
        'ap-review': 'A/P Review', 'approved': 'Approved', 'rejected': 'Rejected',
        'archived': 'Archived',
      };
      const label = statusLabels[body.status] || body.status;
      await buildAuditInsert(env, rfpNumber, 'status_change',
        `Request status changed to ${label}`, performer,
        { new_status: body.status }
      ).run();
    }

    // Assignment change
    if (body.assigned_to) {
      await buildAuditInsert(env, rfpNumber, 'assigned',
        `Request assigned to ${body.assigned_to}`, performer,
        { assigned_to: body.assigned_to }
      ).run();
    }
  } catch (e) {
    console.error('Audit log insert failed:', e.message);
  }

  return json({ rfp_number: rfpNumber, message: 'RFP updated' });
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

  await env.DB.batch([
    env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber),
    env.DB.prepare('DELETE FROM dashboard_data WHERE rfp_number = ?').bind(rfpNumber),
  ]);

  return json({ message: 'RFP deleted', rfp_number: rfpNumber });
}


/* ========================================
   MIGRATE
   ======================================== */
async function handleMigrate(env) {
  const migrations = [
    'ALTER TABLE form_data ADD COLUMN invoice_number TEXT',
    'ALTER TABLE form_data ADD COLUMN invoice_date TEXT',
    'ALTER TABLE form_data ADD COLUMN budget_code TEXT',
    'ALTER TABLE form_data ADD COLUMN account_code TEXT',
    'ALTER TABLE form_data ADD COLUMN submission_type TEXT',
    'ALTER TABLE form_data ADD COLUMN course TEXT',
    'ALTER TABLE form_data ADD COLUMN mileage_from TEXT',
    'ALTER TABLE form_data ADD COLUMN mileage_to TEXT',
  ];

  const results = [];
  for (const sql of migrations) {
    try {
      await env.DB.exec(sql);
      results.push({ sql, status: 'applied' });
    } catch (e) {
      results.push({ sql, status: 'skipped', reason: e.message });
    }
  }

  return json({ message: 'Migration complete', results });
}


/* ========================================
   AUDIT LOGS – GET
   ======================================== */
async function handleGetAuditLog(rfpNumber, env) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY performed_at ASC, id ASC'
  ).bind(rfpNumber).all();

  return json({ audit_logs: results, count: results.length });
}


/* ========================================
   AUDIT LOGS – ADD
   ======================================== */
async function handleAddAuditLog(rfpNumber, request, env) {
  const body = await request.json();

  if (!body.action || !body.description) {
    return json({ error: 'action and description are required' }, 400);
  }

  await env.DB.prepare(`
    INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_at, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    rfpNumber,
    body.action,
    body.description,
    body.performed_by || null,
    body.performed_at || new Date().toISOString(),
    body.metadata ? JSON.stringify(body.metadata) : null,
  ).run();

  return json({ message: 'Audit log entry added', rfp_number: rfpNumber }, 201);
}


/* ========================================
   AUDIT LOGS – HELPER (internal use)
   ======================================== */
function buildAuditInsert(env, rfpNumber, action, description, performedBy, metadata) {
  return env.DB.prepare(`
    INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_at, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    rfpNumber,
    action,
    description,
    performedBy || null,
    new Date().toISOString(),
    metadata ? JSON.stringify(metadata) : null,
  );
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
   MILEAGE – SITES LIST
   ======================================== */
async function handleMileageSites(env) {
  const { results } = await env.DB.prepare(
    'SELECT DISTINCT from_site AS site FROM mileage_table UNION SELECT DISTINCT to_site AS site FROM mileage_table ORDER BY site'
  ).all();
  return json({ sites: results.map(r => r.site) });
}


/* ========================================
   MILEAGE – DISTANCE LOOKUP
   ======================================== */
async function handleMileageDistance(env, url) {
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!from || !to) return json({ error: 'Missing from/to parameters' }, 400);

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

  const prompt = `You are an invoice data extraction assistant. Analyze this PDF document and extract line item details.

Return ONLY valid JSON with this exact structure — no markdown, no code fences, no extra text:
{
  "lineItems": [
    {
      "description": "Item description (uppercase)",
      "invoiceNumber": "Invoice number or empty string",
      "invoiceDate": "MM/DD/YYYY format or empty string",
      "amount": 123.45
    }
  ],
  "vendorName": "Vendor/company name if found, or empty string",
  "vendorNumber": "Vendor/account number if found, or empty string",
  "invoiceTotal": 0.00,
  "confidence": "high|medium|low"
}

Rules:
- Extract ALL line items with their individual amounts
- Descriptions should be UPPERCASE
- Dates must be MM/DD/YYYY format
- Amounts must be numeric (no $ or commas)
- If a single invoice total is shown but no line items, create one line item with the full description and total
- If the document is not an invoice or contains no extractable data, return {"lineItems":[],"confidence":"low"}
- invoiceTotal should be the document's stated total (for verification)`;

  try {
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
        temperature: 0.1,
        maxOutputTokens: 4096,
      }
    };

    const resp = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(geminiBody),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('Gemini API error:', resp.status, errText);
      return json({ error: 'Gemini API error', status: resp.status, detail: errText }, 502);
    }

    const geminiData = await resp.json();

    // Extract text from Gemini response
    const rawText = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '';

    // Clean any markdown fences
    const cleaned = rawText.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();

    let extracted;
    try {
      extracted = JSON.parse(cleaned);
    } catch (parseErr) {
      return json({ error: 'Failed to parse Gemini response', raw: rawText }, 422);
    }

    return json({
      success: true,
      fileName: fileName || 'unknown',
      ...extracted,
    });

  } catch (e) {
    console.error('Extract invoice error:', e);
    return json({ error: 'Extraction failed', detail: e.message }, 500);
  }
}
