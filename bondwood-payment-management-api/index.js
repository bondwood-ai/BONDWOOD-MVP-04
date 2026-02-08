/**
 * bondwood-payment-management-api
 * Independent worker for Bondwood Payment Management frontend.
 * Binds to the same D1 database but does NOT share code with bondwood-api.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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
        return json({ status: 'ok', worker: 'bondwood-payment-management-api', timestamp: new Date().toISOString() });
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

      const rfpMatch = path.match(/^\/api\/rfps\/(\d+)$/);
      if (rfpMatch) {
        const rfpNumber = parseInt(rfpMatch[1]);
        if (method === 'GET') return handleGetRFP(rfpNumber, env);
        if (method === 'PUT') return handleUpdateRFP(rfpNumber, request, env);
        if (method === 'DELETE') return handleDeleteRFP(rfpNumber, env);
      }

      // ── Migrate ──
      if (path === '/api/migrate' && method === 'POST') {
        return handleMigrate(env);
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
    'SELECT vendor_name, vendor_number, vendor_address, vendor_city, vendor_state, vendor_zip FROM vendors ORDER BY vendor_name LIMIT ? OFFSET ?'
  ).bind(limit, offset).all();

  const { results: countResult } = await env.DB.prepare('SELECT COUNT(*) as total FROM vendors').all();
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
  const { results } = await env.DB.prepare(
    'SELECT * FROM districts ORDER BY district_name'
  ).all();

  return json({ districts: results, total: results.length });
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
    SELECT d.*, COALESCE(SUM(f.total), 0) as total_amount
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
    'SELECT * FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!header.length) {
    return json({ error: 'RFP not found' }, 404);
  }

  const { results: lineItems } = await env.DB.prepare(
    'SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number'
  ).bind(rfpNumber).all();

  return json({ ...header[0], lineItems });
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

  if (body.lineItems && body.lineItems.length) {
    for (const item of body.lineItems) {
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

  await env.DB.batch(statements);

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

  // Replace line items if provided
  if (body.lineItems) {
    statements.push(
      env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber)
    );

    for (const item of body.lineItems) {
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

  if (statements.length) {
    await env.DB.batch(statements);
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
