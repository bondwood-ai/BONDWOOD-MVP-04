/**
 * Bondwood Payment Management API
 * Cloudflare Worker + D1 Database
 *
 * Tables:
 *   dashboard_data  – RFP header/status (one row per request)
 *   form_data       – Line items (many rows per RFP, linked by rfp_number)
 *   vendor_data     – Vendor lookup (1,616 vendors)
 *   district_metadata – District brand data (513 districts)
 *   budget_code      – Budget/account code lookup (1,782 rows)
 */

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------
const ALLOWED_ORIGINS = [
  'https://bondwood-mvp-04.pages.dev',
  'http://localhost:8788',
  'http://localhost:3000',
  'http://127.0.0.1:8788',
];

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
  });
}

// ---------------------------------------------------------------------------
// ROUTER
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ── Vendors ──────────────────────────────────────────────────
      if (path === '/api/vendors' && method === 'GET') {
        return handleVendorSearch(url, env, request);
      }

      // ── RFPs (dashboard_data) ────────────────────────────────────
      if (path === '/api/rfps' && method === 'GET') {
        return handleListRFPs(url, env, request);
      }
      if (path === '/api/rfps' && method === 'POST') {
        return handleCreateRFP(request, env);
      }

      // ── Single RFP ──────────────────────────────────────────────
      const rfpMatch = path.match(/^\/api\/rfps\/(\d+)$/);
      if (rfpMatch) {
        const rfpNumber = parseInt(rfpMatch[1]);
        if (method === 'GET') return handleGetRFP(rfpNumber, env, request);
        if (method === 'PUT') return handleUpdateRFP(rfpNumber, request, env);
        if (method === 'DELETE') return handleDeleteRFP(rfpNumber, env, request);
      }

      // ── RFP Status Update ───────────────────────────────────────
      const statusMatch = path.match(/^\/api\/rfps\/(\d+)\/status$/);
      if (statusMatch && method === 'PATCH') {
        return handleUpdateStatus(parseInt(statusMatch[1]), request, env);
      }

      // ── RFP Submit for Approval ─────────────────────────────────
      const submitMatch = path.match(/^\/api\/rfps\/(\d+)\/submit$/);
      if (submitMatch && method === 'POST') {
        return handleSubmitForApproval(parseInt(submitMatch[1]), request, env);
      }

      // ── Line Items ──────────────────────────────────────────────
      const lineItemsMatch = path.match(/^\/api\/rfps\/(\d+)\/line-items$/);
      if (lineItemsMatch) {
        const rfpNumber = parseInt(lineItemsMatch[1]);
        if (method === 'GET') return handleGetLineItems(rfpNumber, env, request);
        if (method === 'PUT') return handleReplaceLineItems(rfpNumber, request, env);
      }

      // ── Stats ───────────────────────────────────────────────────
      if (path === '/api/stats' && method === 'GET') {
        return handleStats(env, request);
      }

      // ── Districts (brand data) ────────────────────────────────────
      if (path === '/api/districts' && method === 'GET') {
        return handleDistricts(url, env, request);
      }

      // ── Budget Codes ────────────────────────────────────────────
      if (path === '/api/budget-codes' && method === 'GET') {
        return handleBudgetCodes(env, request);
      }

      // ── Current User (from SSO) ────────────────────────────────
      if (path === '/api/me' && method === 'GET') {
        return handleMe(request, env);
      }

      // ── Health ──────────────────────────────────────────────────
      if (path === '/api/health') {
        return json({ status: 'ok', timestamp: new Date().toISOString() }, 200, request);
      }

      return json({ error: 'Not found' }, 404, request);
    } catch (err) {
      console.error('API Error:', err);
      return json({ error: err.message || 'Internal server error' }, 500, request);
    }
  },
};

// ===========================================================================
// VENDOR ENDPOINTS
// ===========================================================================

/**
 * GET /api/vendors?search=term&field=name|number&limit=30
 */
async function handleVendorSearch(url, env, request) {
  const search = (url.searchParams.get('search') || '').trim();
  const field = url.searchParams.get('field') || 'both'; // name, number, both
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '30'), 2000);

  if (!search) {
    const { results } = await env.DB.prepare(
      'SELECT * FROM vendor_data ORDER BY vendor_name LIMIT ?'
    ).bind(limit).all();
    return json({ vendors: results, count: results.length }, 200, request);
  }

  let query, params;
  const wildcard = `%${search}%`;

  if (field === 'name') {
    query = 'SELECT * FROM vendor_data WHERE vendor_name LIKE ? ORDER BY vendor_name LIMIT ?';
    params = [wildcard, limit];
  } else if (field === 'number') {
    query = 'SELECT * FROM vendor_data WHERE vendor_number LIKE ? ORDER BY vendor_number LIMIT ?';
    params = [wildcard, limit];
  } else {
    query = `SELECT * FROM vendor_data
             WHERE vendor_name LIKE ? OR vendor_number LIKE ?
             ORDER BY vendor_name LIMIT ?`;
    params = [wildcard, wildcard, limit];
  }

  const { results } = await env.DB.prepare(query).bind(...params).all();
  return json({ vendors: results, count: results.length }, 200, request);
}

// ===========================================================================
// DISTRICT METADATA (BRAND DATA)
// ===========================================================================

/**
 * GET /api/districts?member_org=AMSD&search=term
 * Returns all districts or filtered by member_org / search term
 */
async function handleDistricts(url, env, request) {
  const memberOrg = url.searchParams.get('member_org');
  const search = (url.searchParams.get('search') || '').trim();

  let query = 'SELECT * FROM district_metadata';
  let params = [];
  let clauses = [];

  if (memberOrg) {
    clauses.push('Member_Org = ?');
    params.push(memberOrg);
  }

  if (search) {
    clauses.push('(District_Name LIKE ? OR CAST(District_Number AS TEXT) LIKE ?)');
    const wildcard = `%${search}%`;
    params.push(wildcard, wildcard);
  }

  if (clauses.length) {
    query += ' WHERE ' + clauses.join(' AND ');
  }

  query += ' ORDER BY District_Name';

  const { results } = await env.DB.prepare(query).bind(...params).all();
  return json(results, 200, request);
}

// ===========================================================================
// RFP LIST & STATS
// ===========================================================================

/**
 * GET /api/rfps?page=1&limit=250&status=all&search=term&sort=rfp_number&dir=desc
 */
async function handleListRFPs(url, env, request) {
  const page = Math.max(1, parseInt(url.searchParams.get('page') || '1'));
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '250'), 500);
  const status = url.searchParams.get('status') || 'all';
  const search = (url.searchParams.get('search') || '').trim();
  const sort = url.searchParams.get('sort') || 'rfp_number';
  const dir = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
  const offset = (page - 1) * limit;

  // Whitelist sort columns
  const validSorts = ['rfp_number', 'submitter_name', 'submission_date', 'status', 'vendor_name', 'assigned_to', 'ap_batch'];
  const sortCol = validSorts.includes(sort) ? sort : 'rfp_number';

  let whereClauses = [];
  let params = [];

  if (status !== 'all') {
    whereClauses.push('d.status = ?');
    params.push(status);
  }

  if (search) {
    whereClauses.push(`(
      d.rfp_number LIKE ? OR
      d.submitter_name LIKE ? OR
      d.vendor_name LIKE ? OR
      d.assigned_to LIKE ? OR
      d.invoice_number LIKE ?
    )`);
    const wildcard = `%${search}%`;
    params.push(wildcard, wildcard, wildcard, wildcard, wildcard);
  }

  const whereSQL = whereClauses.length ? 'WHERE ' + whereClauses.join(' AND ') : '';

  // Get total count
  const countQuery = `SELECT COUNT(DISTINCT d.id) as total
                      FROM dashboard_data d ${whereSQL}`;
  const { results: countResult } = await env.DB.prepare(countQuery).bind(...params).all();
  const total = countResult[0]?.total || 0;

  // Get paginated results with computed amount from line items
  const dataQuery = `
    SELECT d.*,
           COALESCE(SUM(f.total), 0) + COALESCE(d.mileage_total, 0) AS amount,
           julianday('now') - julianday(d.submission_date) AS days_since_submission
    FROM dashboard_data d
    LEFT JOIN form_data f ON d.rfp_number = f.rfp_number
    ${whereSQL}
    GROUP BY d.id
    ORDER BY ${sortCol} ${dir}
    LIMIT ? OFFSET ?
  `;
  params.push(limit, offset);

  const { results } = await env.DB.prepare(dataQuery).bind(...params).all();

  return json({
    rfps: results,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  }, 200, request);
}

/**
 * GET /api/stats
 */
async function handleStats(env, request) {
  const queries = {
    total: 'SELECT COUNT(*) as count FROM dashboard_data',
    inProgress: `SELECT COUNT(*) as count FROM dashboard_data WHERE status IN ('submitted','budget-review','compliance-review','ap-review')`,
    approved: `SELECT COUNT(*) as count FROM dashboard_data WHERE status = 'approved'`,
    rejected: `SELECT COUNT(*) as count FROM dashboard_data WHERE status = 'rejected'`,
    draft: `SELECT COUNT(*) as count FROM dashboard_data WHERE status = 'draft'`,
    totalAmount: `SELECT COALESCE(SUM(f.total), 0) + COALESCE(SUM(DISTINCT d.mileage_total), 0) as amount
                  FROM dashboard_data d LEFT JOIN form_data f ON d.rfp_number = f.rfp_number`,
  };

  const results = {};
  for (const [key, sql] of Object.entries(queries)) {
    const { results: rows } = await env.DB.prepare(sql).all();
    results[key] = rows[0]?.count ?? rows[0]?.amount ?? 0;
  }

  return json(results, 200, request);
}

// ===========================================================================
// SINGLE RFP CRUD
// ===========================================================================

/**
 * GET /api/rfps/:rfpNumber – Full RFP with line items
 */
async function handleGetRFP(rfpNumber, env, request) {
  const { results: headers } = await env.DB.prepare(
    'SELECT * FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!headers.length) {
    return json({ error: 'RFP not found' }, 404, request);
  }

  const { results: lineItems } = await env.DB.prepare(
    'SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number'
  ).bind(rfpNumber).all();

  return json({ ...headers[0], lineItems }, 200, request);
}

/**
 * POST /api/rfps – Create new RFP + line items
 * Body: { submitter_name, submitter_id, request_type, vendor_name, ..., lineItems: [...] }
 */
async function handleCreateRFP(request, env) {
  const body = await request.json();

  // Generate next RFP number
  const { results: maxRow } = await env.DB.prepare(
    'SELECT MAX(rfp_number) as max_num FROM dashboard_data'
  ).all();
  const nextRfp = (maxRow[0]?.max_num || 2600000) + 1;

  // Insert header
  const headerStmt = env.DB.prepare(`
    INSERT INTO dashboard_data (
      rfp_number, submitter_name, submitter_id, budget_approver,
      submission_date, request_type, vendor_name, vendor_number,
      vendor_address, invoice_number, employee_name, employee_id,
      description, status, assigned_to, ap_batch, mileage_total
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const status = body.status || 'draft';
  const submissionDate = body.submission_date || new Date().toISOString().split('T')[0];

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

  // Batch: header + line items
  const statements = [headerStmt.bind(...headerParams)];

  if (body.lineItems && body.lineItems.length) {
    for (const item of body.lineItems) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO form_data (rfp_number, line_number, description, fund, organization, program, finance, object, quantity, unit_price, total)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          nextRfp,
          item.line_number || 0,
          item.description || '',
          item.fund || null,
          item.organization || null,
          item.program || null,
          item.finance || null,
          item.object || null,
          item.quantity || 0,
          item.unit_price || 0,
          item.total || 0,
        )
      );
    }
  }

  await env.DB.batch(statements);

  return json({ rfp_number: nextRfp, status, message: 'RFP created' }, 201, request);
}

/**
 * PUT /api/rfps/:rfpNumber – Update RFP header + replace line items
 */
async function handleUpdateRFP(rfpNumber, request, env) {
  const body = await request.json();

  // Verify exists
  const { results: existing } = await env.DB.prepare(
    'SELECT id FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!existing.length) {
    return json({ error: 'RFP not found' }, 404, request);
  }

  // Build dynamic UPDATE for header
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

  setClauses.push("updated_at = datetime('now')");

  const statements = [];

  if (setClauses.length > 1) { // More than just updated_at
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
          INSERT INTO form_data (rfp_number, line_number, description, fund, organization, program, finance, object, quantity, unit_price, total)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          rfpNumber,
          item.line_number || 0,
          item.description || '',
          item.fund || null,
          item.organization || null,
          item.program || null,
          item.finance || null,
          item.object || null,
          item.quantity || 0,
          item.unit_price || 0,
          item.total || 0,
        )
      );
    }
  }

  if (statements.length) {
    await env.DB.batch(statements);
  }

  return json({ rfp_number: rfpNumber, message: 'RFP updated' }, 200, request);
}

/**
 * DELETE /api/rfps/:rfpNumber
 */
async function handleDeleteRFP(rfpNumber, env, request) {
  const statements = [
    env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber),
    env.DB.prepare('DELETE FROM dashboard_data WHERE rfp_number = ?').bind(rfpNumber),
  ];

  await env.DB.batch(statements);
  return json({ rfp_number: rfpNumber, message: 'RFP deleted' }, 200, request);
}

// ===========================================================================
// STATUS & WORKFLOW
// ===========================================================================

/**
 * PATCH /api/rfps/:rfpNumber/status
 * Body: { status, assigned_to? }
 */
async function handleUpdateStatus(rfpNumber, request, env) {
  const body = await request.json();

  if (!body.status) {
    return json({ error: 'Status is required' }, 400, request);
  }

  const validStatuses = ['draft', 'submitted', 'budget-review', 'compliance-review', 'ap-review', 'approved', 'rejected', 'archived'];
  if (!validStatuses.includes(body.status)) {
    return json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` }, 400, request);
  }

  let query = `UPDATE dashboard_data SET status = ?, updated_at = datetime('now')`;
  let params = [body.status];

  if (body.assigned_to !== undefined) {
    query += ', assigned_to = ?';
    params.push(body.assigned_to);
  }

  if (body.ap_batch !== undefined) {
    query += ', ap_batch = ?';
    params.push(body.ap_batch);
  }

  query += ' WHERE rfp_number = ?';
  params.push(rfpNumber);

  await env.DB.prepare(query).bind(...params).run();

  return json({ rfp_number: rfpNumber, status: body.status, message: 'Status updated' }, 200, request);
}

/**
 * POST /api/rfps/:rfpNumber/submit
 * Body: { signature_name }
 */
async function handleSubmitForApproval(rfpNumber, request, env) {
  const body = await request.json();

  if (!body.signature_name) {
    return json({ error: 'Signature name is required' }, 400, request);
  }

  // Verify RFP exists and is in draft status
  const { results } = await env.DB.prepare(
    'SELECT status FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!results.length) {
    return json({ error: 'RFP not found' }, 404, request);
  }

  await env.DB.prepare(`
    UPDATE dashboard_data
    SET status = 'submitted',
        submission_date = date('now'),
        updated_at = datetime('now')
    WHERE rfp_number = ?
  `).bind(rfpNumber).run();

  return json({
    rfp_number: rfpNumber,
    status: 'submitted',
    signature_name: body.signature_name,
    submitted_at: new Date().toISOString(),
    message: 'RFP submitted for approval',
  }, 200, request);
}

// ===========================================================================
// LINE ITEMS
// ===========================================================================

/**
 * GET /api/rfps/:rfpNumber/line-items
 */
async function handleGetLineItems(rfpNumber, env, request) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM form_data WHERE rfp_number = ? ORDER BY line_number'
  ).bind(rfpNumber).all();

  return json({ rfp_number: rfpNumber, lineItems: results, count: results.length }, 200, request);
}

/**
 * PUT /api/rfps/:rfpNumber/line-items – Replace all line items
 * Body: { lineItems: [...] }
 */
async function handleReplaceLineItems(rfpNumber, request, env) {
  const body = await request.json();

  if (!body.lineItems || !Array.isArray(body.lineItems)) {
    return json({ error: 'lineItems array is required' }, 400, request);
  }

  const statements = [
    env.DB.prepare('DELETE FROM form_data WHERE rfp_number = ?').bind(rfpNumber),
  ];

  for (const item of body.lineItems) {
    statements.push(
      env.DB.prepare(`
        INSERT INTO form_data (rfp_number, line_number, description, fund, organization, program, finance, object, quantity, unit_price, total)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        rfpNumber,
        item.line_number || 0,
        item.description || '',
        item.fund || null,
        item.organization || null,
        item.program || null,
        item.finance || null,
        item.object || null,
        item.quantity || 0,
        item.unit_price || 0,
        item.total || 0,
      )
    );
  }

  await env.DB.batch(statements);

  return json({
    rfp_number: rfpNumber,
    message: 'Line items replaced',
    count: body.lineItems.length,
  }, 200, request);
}

// ===========================================================================
// BUDGET CODES
// ===========================================================================

/**
 * GET /api/budget-codes
 * Returns all budget_code rows for frontend autocomplete
 */
async function handleBudgetCodes(env, request) {
  const { results } = await env.DB.prepare(
    `SELECT budget_code, account_code, fund, organization, program, finance, course
     FROM budget_code
     ORDER BY budget_code, account_code`
  ).all();

  return new Response(JSON.stringify(results), {
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

/**
 * GET /api/me
 * Returns current user info based on SSO identity.
 * Tries (in order):
 *   1. Cf-Access-Authenticated-User-Email header (worker behind Access)
 *   2. CF_Authorization cookie JWT decode (Pages behind Access, cross-origin fetch)
 *   3. ?email= query param (for testing)
 */
async function handleMe(request, env) {
  const url = new URL(request.url);
  let email = '';

  // Method 1: CF Access header
  email = (request.headers.get('Cf-Access-Authenticated-User-Email') || '').trim().toLowerCase();

  // Method 2: Decode CF_Authorization cookie
  if (!email) {
    try {
      const cookieHeader = request.headers.get('Cookie') || '';
      const match = cookieHeader.match(/CF_Authorization=([^;]+)/);
      if (match) {
        const payload = JSON.parse(atob(match[1].split('.')[1]));
        email = (payload.email || '').trim().toLowerCase();
      }
    } catch (e) { /* ignore decode errors */ }
  }

  // Method 3: Query param fallback (testing only)
  if (!email) {
    email = (url.searchParams.get('email') || '').trim().toLowerCase();
  }

  if (!email) {
    return json({ error: 'No SSO email found' }, 401, request);
  }

  const user = await env.DB.prepare(
    'SELECT user_id, user_first_name, user_last_name, user_email FROM user_data WHERE LOWER(user_email) = ? LIMIT 1'
  ).bind(email).first();

  if (!user) {
    return json({ error: 'User not found', email }, 404, request);
  }

  return json({
    user_id: user.user_id,
    first_name: user.user_first_name,
    last_name: user.user_last_name,
    email: user.user_email
  }, 200, request);
}
