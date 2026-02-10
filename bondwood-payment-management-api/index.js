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
    'ALTER TABLE dashboard_data ADD COLUMN creation_source TEXT',
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
