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

// Parse a 14-char budget code into its 5 segments: fund(2) + org(3) + program(3) + finance(3) + course(3)
function parseBudgetSegments(budgetCode) {
  const c = (budgetCode || '').toString().replace(/[^0-9]/g, '');
  if (c.length < 14) return { fund: null, organization: null, program: null, finance: null, course: null };
  return {
    fund: c.substring(0, 2),
    organization: c.substring(2, 5),
    program: c.substring(5, 8),
    finance: c.substring(8, 11),
    course: c.substring(11, 14),
  };
}

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

      // ── Workflow Actions (approve/reject/return) ──
      const wfMatch = path.match(/^\/api\/rfps\/(\d+)\/workflow-action$/);
      if (wfMatch && method === 'POST') {
        return handleWorkflowAction(parseInt(wfMatch[1]), request, env);
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

      // ── Notes ──
      const notesMatch = path.match(/^\/api\/rfps\/(\d+)\/notes$/);
      if (notesMatch) {
        const rfpNumber = parseInt(notesMatch[1]);
        if (method === 'GET') return handleGetNotes(rfpNumber, env);
        if (method === 'POST') return handleCreateNote(rfpNumber, request, env);
      }

      // ── Users ──
      if (path === '/api/users' && method === 'GET') {
        return handleGetUsers(env);
      }
      if (path === '/api/users/status' && method === 'PUT') {
        return handleUpdateUserStatus(request, env);
      }
      if (path === '/api/users/roles' && method === 'PUT') {
        return handleUpdateUserRoles(request, env);
      }
      if (path === '/api/users/restriction-groups' && method === 'PUT') {
        return handleUpdateUserRestrictionGroups(request, env);
      }
      if (path === '/api/users/restriction-rules' && method === 'GET') {
        return handleGetUserRestrictionRules(url, env);
      }
      if (path === '/api/role-definitions' && method === 'GET') {
        return handleGetRoleDefinitions(env);
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

      if (path === '/api/migrate-form-data-segments' && method === 'POST') {
        return handleMigrateFormDataSegments(env);
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

      // ── Restriction Groups ──
      if (path === '/api/ap-batches' && method === 'GET') {
        const type = url.searchParams.get('type') || '';
        let query = 'SELECT * FROM ap_batch';
        const params = [];
        if (type) { query += ' WHERE ap_batch_type = ?'; params.push(type); }
        query += ' ORDER BY ap_batch_number ASC';
        const { results } = await env.DB.prepare(query).bind(...params).all();
        return json({ batches: results });
      }

      if (path === '/api/restriction-groups' && method === 'GET') {
        return handleListRestrictionGroups(env);
      }
      if (path === '/api/restriction-groups' && method === 'POST') {
        return handleCreateRestrictionGroup(request, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+$/) && method === 'PUT') {
        const id = path.split('/').pop();
        return handleUpdateRestrictionGroup(id, request, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+$/) && method === 'DELETE') {
        const id = path.split('/').pop();
        return handleDeleteRestrictionGroup(id, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+\/approvers$/) && method === 'PUT') {
        const id = path.split('/')[3];
        return handleUpdateRgApprovers(id, request, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+\/budget-rules$/) && method === 'POST') {
        const id = path.split('/')[3];
        return handleAddRgBudgetRule(id, request, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+\/budget-rules\/\d+$/) && method === 'DELETE') {
        const parts = path.split('/');
        return handleDeleteRgBudgetRule(parts[3], parts[5], env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+\/vendors$/) && method === 'POST') {
        const id = path.split('/')[3];
        return handleAddRgVendors(id, request, env);
      }
      if (path.match(/^\/api\/restriction-groups\/\d+\/vendors\//) && method === 'DELETE') {
        const parts = path.split('/');
        const vendorNum = decodeURIComponent(parts.slice(5).join('/'));
        return handleDeleteRgVendor(parts[3], vendorNum, env);
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
    'SELECT user_id, user_first_name, user_last_name, user_email, phone_number, department, title, profile_picture_key, user_roles, status FROM user_data WHERE LOWER(user_email) = ?'
  ).bind(email.toLowerCase().trim()).all();

  if (!results.length) {
    // Auto-provision new user with default "submitter" role
    const emailLower = email.toLowerCase().trim();
    const nameParts = emailLower.split('@')[0].split('.');
    const firstName = nameParts[0] ? nameParts[0].charAt(0).toUpperCase() + nameParts[0].slice(1) : '';
    const lastName = nameParts[1] ? nameParts[1].charAt(0).toUpperCase() + nameParts[1].slice(1) : '';

    // Generate a unique user_id
    let userId;
    try {
      const { results: seqRows } = await env.DB.prepare(
        "SELECT seq FROM sqlite_sequence WHERE name = 'user_data'"
      ).all();
      userId = String((seqRows[0]?.seq || 99999) + 1);
    } catch (e) { userId = String(Date.now()).slice(-6); }

    try {
      await env.DB.prepare(
        'INSERT INTO user_data (user_id, user_email, user_first_name, user_last_name, user_roles, status) VALUES (?, ?, ?, ?, ?, ?)'
      ).bind(userId, emailLower, firstName, lastName, '["submitter"]', 'active').run();

      return json({
        user_id: userId,
        first_name: firstName,
        last_name: lastName,
        email: emailLower,
        phone_number: '',
        department: '',
        title: '',
        profile_picture_key: null,
        roles: ['submitter'],
        permissions: {},
      });
    } catch (e) {
      return json({ error: 'Failed to provision user: ' + e.message }, 500);
    }
  }

  const u = results[0];

  // Block deactivated users
  if (u.status === 'inactive') {
    return json({ error: 'account_deactivated', message: 'Your account has been deactivated. Please contact an administrator.' }, 403);
  }

  // Parse roles from JSON column
  let roles = [];
  try { roles = JSON.parse(u.user_roles || '["user"]'); } catch (e) { roles = ['user']; }

  // Derive permissions from roles
  const isSuperUser = roles.includes('super_user');
  const isAdmin = roles.includes('admin') || isSuperUser;
  const isAccountant = roles.includes('accountant');
  const isAP = roles.includes('accounts_payable');
  const permissions = {
    can_manage_users: isSuperUser,
    can_manage_vendors: isAdmin,
    can_approve: isAdmin || isAccountant || isAP,
    can_reject: isAdmin || isAccountant || isAP,
    can_assign: isAdmin,
    can_view_all: isAdmin || isAccountant || isAP,
    can_export: isAdmin,
    can_import: isAdmin,
  };

  // Fetch user's restriction group budget rules
  let budget_rules = [];
  let restricted_vendors = [];
  let restriction_groups = [];
  try {
    const emailLower = (u.user_email || '').toLowerCase();
    const { results: assignments } = await env.DB.prepare(
      'SELECT group_id FROM user_restriction_assignments WHERE LOWER(user_email) = ?'
    ).bind(emailLower).all();

    if (assignments.length > 0) {
      const groupIds = assignments.map(a => a.group_id);
      const placeholders = groupIds.map(() => '?').join(',');

      const { results: groups } = await env.DB.prepare(
        `SELECT id, name FROM restriction_groups WHERE id IN (${placeholders})`
      ).bind(...groupIds).all();
      restriction_groups = groups;

      const { results: rules } = await env.DB.prepare(
        `SELECT fund, organization, program, finance, course FROM restriction_group_budget_rules WHERE group_id IN (${placeholders})`
      ).bind(...groupIds).all();
      budget_rules = rules;

      const { results: vendors } = await env.DB.prepare(
        `SELECT vendor_number FROM restriction_group_vendors WHERE group_id IN (${placeholders})`
      ).bind(...groupIds).all();
      restricted_vendors = vendors.map(v => v.vendor_number);
    }
  } catch (e) {}

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
    permissions,
    budget_rules,
    restricted_vendors,
    restriction_groups,
  });
}


/* ========================================
   USER PREFERENCES
   ======================================== */
function getEmailFromRequest(request) {
  const url = new URL(request.url);
  let email = url.searchParams.get('email');
  if (!email) email = request.headers.get('Cf-Access-Authenticated-User-Email');
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
      'SELECT preferences FROM user_data WHERE LOWER(user_email) = ?'
    ).bind(email).all();

    if (!results.length) return json({ prefs: null });

    const raw = results[0].preferences;
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
    'UPDATE user_data SET preferences = ? WHERE LOWER(user_email) = ?'
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
   RFPs – ADVANCED SEARCH OPTIONS
   ======================================== */
async function handleSearchOptions(env) {
  try {
    const [
      statusR, typeR, submitterR, assignedR, batchR,
      vendorNameR, vendorNumR, descR, invNumR,
      budgetCodeR, acctCodeR, fundR, orgR, progR, finR, courseR
    ] = await Promise.all([
      env.DB.prepare("SELECT DISTINCT status FROM dashboard_data WHERE status IS NOT NULL AND status != '' ORDER BY status").all(),
      env.DB.prepare("SELECT DISTINCT request_type FROM dashboard_data WHERE request_type IS NOT NULL AND request_type != '' ORDER BY request_type").all(),
      env.DB.prepare("SELECT DISTINCT submitter_name FROM dashboard_data WHERE submitter_name IS NOT NULL AND submitter_name != '' ORDER BY submitter_name").all(),
      env.DB.prepare("SELECT DISTINCT assigned_to FROM dashboard_data WHERE assigned_to IS NOT NULL AND assigned_to != '' ORDER BY assigned_to").all(),
      env.DB.prepare("SELECT DISTINCT ap_batch FROM dashboard_data WHERE ap_batch IS NOT NULL AND ap_batch != '' ORDER BY ap_batch").all(),
      env.DB.prepare("SELECT DISTINCT vendor_name FROM dashboard_data WHERE vendor_name IS NOT NULL AND vendor_name != '' ORDER BY vendor_name").all(),
      env.DB.prepare("SELECT DISTINCT vendor_number FROM dashboard_data WHERE vendor_number IS NOT NULL AND vendor_number != '' ORDER BY vendor_number").all(),
      env.DB.prepare("SELECT DISTINCT description FROM form_data WHERE description IS NOT NULL AND description != '' ORDER BY description").all(),
      env.DB.prepare("SELECT DISTINCT invoice_number FROM form_data WHERE invoice_number IS NOT NULL AND invoice_number != '' ORDER BY invoice_number").all(),
      env.DB.prepare("SELECT DISTINCT budget_code FROM form_data WHERE budget_code IS NOT NULL AND budget_code != '' ORDER BY budget_code").all(),
      env.DB.prepare("SELECT DISTINCT COALESCE(account_code, object) AS account_code FROM form_data WHERE (account_code IS NOT NULL AND account_code != '') OR (object IS NOT NULL AND object != '') ORDER BY 1").all(),
      env.DB.prepare("SELECT DISTINCT fund FROM form_data WHERE fund IS NOT NULL AND fund != '' ORDER BY fund").all(),
      env.DB.prepare("SELECT DISTINCT organization FROM form_data WHERE organization IS NOT NULL AND organization != '' ORDER BY organization").all(),
      env.DB.prepare("SELECT DISTINCT program FROM form_data WHERE program IS NOT NULL AND program != '' ORDER BY program").all(),
      env.DB.prepare("SELECT DISTINCT finance FROM form_data WHERE finance IS NOT NULL AND finance != '' ORDER BY finance").all(),
      env.DB.prepare("SELECT DISTINCT object FROM form_data WHERE object IS NOT NULL AND object != '' ORDER BY object").all(),
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
      course: pluck(courseR, 'object'),
    });
  } catch (e) {
    return json({ error: 'Failed to fetch search options', detail: e.message }, 500);
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
  const email = (url.searchParams.get('email') || '').toLowerCase().trim();
  const forSubmitterId = url.searchParams.get('for_submitter_id') || '';

  // If no email provided, return empty — never return all RFPs unfiltered
  if (!email) {
    return json({ rfps: [], total: 0, page: 1, limit });
  }

  const allowedSorts = ['rfp_number', 'submission_date', 'submitter_name', 'vendor_name', 'status'];
  const sortCol = allowedSorts.includes(sort) ? sort : 'rfp_number';

  let where = ['d.deleted_at IS NULL'];
  let params = [];

  // Check if the requesting user is an admin — if not, filter to only their RFPs
  if (email) {
    let isAdmin = false;
    let canViewAll = false;
    let submitterId = null;
    let submitterName = null;
    try {
      const { results: userRows } = await env.DB.prepare(
        'SELECT user_id, user_roles, user_first_name, user_last_name FROM user_data WHERE LOWER(user_email) = ?'
      ).bind(email).all();
      if (userRows.length) {
        const roles = JSON.parse(userRows[0].user_roles || '["user"]');
        isAdmin = roles.includes('super_user') || roles.includes('admin');
        canViewAll = isAdmin || roles.includes('accountant') || roles.includes('accounts_payable');
        submitterId = 'E' + userRows[0].user_id;
        submitterName = ((userRows[0].user_first_name || '') + ' ' + (userRows[0].user_last_name || '')).trim().toUpperCase();
      }
    } catch (e) {}

    // Admin filtering for a specific submitter (e.g. user detail panel)
    if (canViewAll && forSubmitterId) {
      const forEmail = (url.searchParams.get('for_submitter_email') || '').toLowerCase().trim();
      const sid = forSubmitterId.toUpperCase();
      const sidNoE = sid.replace(/^E/i, '');
      
      // Match by user_email (primary), or fall back to submitter_id for older records
      if (forEmail) {
        where.push('(LOWER(d.user_email) = ? OR UPPER(d.submitter_id) = UPPER(?) OR UPPER(d.submitter_id) = UPPER(?))');
        params.push(forEmail, sid, sidNoE);
      } else {
        where.push('(UPPER(d.submitter_id) = UPPER(?) OR UPPER(d.submitter_id) = UPPER(?))');
        params.push(sid, sidNoE);
      }
    } else if (!canViewAll && submitterId) {
      // User can see: forms they submitted (by email, ID, or name) OR forms assigned to them OR forms they acted on
      where.push('(LOWER(d.user_email) = ? OR UPPER(d.submitter_id) = UPPER(?) OR UPPER(d.submitter_id) = UPPER(?) OR (? != \'\' AND UPPER(d.submitter_name) = ?) OR LOWER(d.assigned_to_email) = ? OR d.rfp_number IN (SELECT DISTINCT rfp_number FROM audit_logs WHERE LOWER(performed_by_email) = ?))');
      params.push(email, submitterId, submitterId.replace(/^E/i, ''), submitterName || '', submitterName || '', email, email);
    } else if (!canViewAll && !submitterId) {
      // User not found in DB — return nothing
      return json({ rfps: [], total: 0, page, limit });
    }
  }

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
      'SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY performed_at ASC, id ASC'
    ).bind(rfpNumber).all();
    auditLogs = logs;
  } catch (e) { /* table may not exist yet */ }

  let notes = [];
  try {
    const { results: noteRows } = await env.DB.prepare(
      'SELECT * FROM rfp_notes WHERE rfp_number = ? ORDER BY created_at ASC'
    ).bind(rfpNumber).all();
    notes = noteRows;
  } catch (e) { /* table may not exist yet */ }

  return json({ ...header[0], lineItems, mileageTrips, auditLogs, notes });
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
      rfp_number, submitter_name, submitter_id, user_email, budget_approver,
      submission_date, request_type, vendor_name, vendor_number,
      vendor_address, invoice_number, employee_name, employee_id,
      description, status, assigned_to, ap_batch, mileage_total, creation_source,
      restriction_group_id, assigned_to_email, approval_history
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const headerParams = [
    nextRfp,
    body.submitter_name || '',
    body.submitter_id || '',
    (body.user_email || '').toLowerCase().trim(),
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
    body.restriction_group_id || null,
    null,
    '[]',
  ];

  const statements = [headerStmt.bind(...headerParams)];

  const newItems = (body.lineItems || []).filter(i => i.description);
  const newTrips = body.mileageTrips || [];

  if (newItems.length) {
    for (const item of newItems) {
      const seg = parseBudgetSegments(item.budget_code);
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
          item.fund || seg.fund,
          item.organization || seg.organization,
          item.program || seg.program,
          item.finance || seg.finance,
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

  await env.DB.batch(statements);

  // Audit log - separate from data batch so it can't break the save
  try {
    const typeLabel = (body.request_type === 'reimbursement') ? 'Employee Reimbursement' : (body.vendor_name || 'Vendor Payment');
    const itemTotal = newItems.reduce((s, i) => s + (i.total || 0), 0);
    const mileageTotal = body.mileage_total || 0;
    const grandTotal = itemTotal + mileageTotal;
    const statusVerb = status === 'submitted' ? 'submitted' : 'created a draft';

    let auditDesc = `<strong>${performer}</strong> ${statusVerb} request for payment with <strong>${typeLabel}</strong> for <strong>$${grandTotal.toFixed(2)}</strong>`;
    const detailParts = [];
    if (newItems.length) detailParts.push(`${newItems.length} line item${newItems.length > 1 ? 's' : ''} ($${itemTotal.toFixed(2)})`);
    if (newTrips.length) detailParts.push(`${newTrips.length} mileage trip${newTrips.length > 1 ? 's' : ''} ($${mileageTotal.toFixed(2)})`);
    if (detailParts.length) auditDesc += ' - ' + detailParts.join(', ');

    const sourceLabel = body.creation_source === 'import' ? ' using the <strong>Import</strong> function'
        : body.creation_source === 'capture' ? ' using the <strong>Capture Invoice</strong> function' : '';
    auditDesc += sourceLabel;

    const now = new Date().toISOString();
    await env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(nextRfp, status === 'submitted' ? 'submitted' : 'draft-created', auditDesc, performer, (body.performer_email || '').toLowerCase().trim() || null, now).run();
  } catch (auditErr) {
    console.error('[AUDIT] Failed to write audit log for create:', auditErr.message);
  }

  // Save description as a note if provided
  if (body.description && body.description.trim()) {
    try {
      await env.DB.prepare(
        'INSERT INTO rfp_notes (rfp_number, note_text, author_name, author_email, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(nextRfp, body.description.trim(), performer, (body.user_email || '').toLowerCase().trim(), new Date().toISOString()).run();
    } catch (e) { console.error('[NOTES] Failed to save note:', e.message); }
  }

  // ── Auto-advance workflow when submitted ──
  if (status === 'submitted') {
    try {
      const advancement = await advanceToNextStep(env, nextRfp, 'submitted', body.restriction_group_id || null);
      if (advancement) {
        await env.DB.prepare(
          'UPDATE dashboard_data SET status = ?, assigned_to = ?, assigned_to_email = ? WHERE rfp_number = ?'
        ).bind(advancement.status, advancement.assignedToName, advancement.assignedToEmail, nextRfp).run();

        const stepLabel = WORKFLOW_STATUS_LABELS[advancement.status] || advancement.status;
        await env.DB.prepare(
          'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(nextRfp, 'workflow-advanced', `Form routed to <strong>${advancement.assignedToName}</strong> for <strong>${stepLabel}</strong>`, 'System', null, new Date().toISOString()).run();
      }
    } catch (wfErr) {
      console.error('[WORKFLOW] Failed to advance after submission:', wfErr.message);
    }
  }

  return json({ rfp_number: nextRfp, status, message: 'RFP created' }, 201);
}


/* ========================================
   RFPs – UPDATE
   ======================================== */
async function handleUpdateRFP(rfpNumber, request, env) {
  const body = await request.json();
  const performer = body.submitter_name || 'Unknown';
  const performerEmail = (body.performer_email || '').toLowerCase().trim();

  // ── Read existing state BEFORE making changes ──
  const { results: existingHeader } = await env.DB.prepare(
    'SELECT * FROM dashboard_data WHERE rfp_number = ?'
  ).bind(rfpNumber).all();

  if (!existingHeader.length) {
    return json({ error: 'RFP not found' }, 404);
  }
  const oldHeader = existingHeader[0];

  // ── APPROVAL GUARD: prevent self-approval and check approver authorization ──
  const approvalStatuses = ['secondary_3_review', 'secondary_2_review', 'secondary_1_review', 'primary_review', 'accounting_review', 'ap_review', 'accounting-review', 'ap-review', 'approved', 'rejected'];
  if (body.status && approvalStatuses.includes(body.status) && performerEmail) {
    // 1. Never allow self-approval/self-advancement
    const submitterId = (oldHeader.submitter_id || '').toUpperCase();

    let performerUserId = null;
    let isAdmin = false;
    let performerRoles = [];
    try {
      const { results: pUser } = await env.DB.prepare(
        'SELECT user_id, user_roles FROM user_data WHERE LOWER(user_email) = ?'
      ).bind(performerEmail).all();
      if (pUser.length) {
        performerUserId = 'E' + pUser[0].user_id;
        performerRoles = JSON.parse(pUser[0].user_roles || '["user"]');
        isAdmin = performerRoles.includes('super_user') || performerRoles.includes('admin');
      }
    } catch (e) {}

    if (performerUserId && performerUserId === submitterId) {
      return json({ error: 'You cannot approve or reject your own submission' }, 403);
    }

    // 2. Check authorization: admin, assigned approver, accountant at their step, or AP at their step
    const isAssigned = (oldHeader.assigned_to_email || '').toLowerCase() === performerEmail;
    const isAccountant = performerRoles.includes('accountant');
    const isAP = performerRoles.includes('accounts_payable');
    const atAccountingStep = oldHeader.status === 'accounting_review' || oldHeader.status === 'accounting-review';
    const atAPStep = oldHeader.status === 'ap_review' || oldHeader.status === 'ap-review';

    if (!isAdmin && !isAssigned && !(isAccountant && atAccountingStep) && !(isAP && atAPStep)) {
      return json({ error: 'You do not have permission to approve or reject this submission' }, 403);
    }
  }

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
    'restriction_group_id', 'assigned_to_email', 'approval_history',
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
      const seg = parseBudgetSegments(item.budget_code);
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
          item.fund || seg.fund,
          item.organization || seg.organization,
          item.program || seg.program,
          item.finance || seg.finance,
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

  if (statements.length) {
    await env.DB.batch(statements);
  }

  // Audit log - separate from data batch so it can't break the save
  let auditDebug = {};
  try {
    console.log('[AUDIT] oldItems count:', oldItems.length, 'oldTrips count:', oldTrips.length);
    console.log('[AUDIT] newItems:', newItems !== null ? newItems.length : 'null', 'newTrips:', newTrips !== null ? newTrips.length : 'null');
    console.log('[AUDIT] body.status:', body.status, 'oldHeader.status:', oldHeader.status);

    const auditEntries = buildAuditEntries(oldHeader, oldItems, oldTrips, body, newItems, newTrips, performer);
    console.log('[AUDIT] Generated entries:', auditEntries.length, JSON.stringify(auditEntries.map(e => e.action)));

    auditDebug = {
      oldItemCount: oldItems.length,
      oldTripCount: oldTrips.length,
      newItemCount: newItems !== null ? newItems.length : 'null',
      newTripCount: newTrips !== null ? newTrips.length : 'null',
      entriesGenerated: auditEntries.length,
      entryActions: auditEntries.map(e => e.action),
    };

    const now = new Date().toISOString();
    for (const entry of auditEntries) {
      await env.DB.prepare(
        'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).bind(rfpNumber, entry.action, entry.description, performer, performerEmail || null, now).run();
    }
    auditDebug.written = true;
  } catch (auditErr) {
    console.error('[AUDIT] Failed:', auditErr.message, auditErr.stack);
    auditDebug.error = auditErr.message;
  }

  return json({ rfp_number: rfpNumber, message: 'RFP updated', _auditDebug: auditDebug });
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

    // Workflow status changes
    const statusLabel = WORKFLOW_STATUS_LABELS[body.status] || body.status;
    const oldStatusLabel = WORKFLOW_STATUS_LABELS[oldHeader.status] || oldHeader.status;

    if (body.status === 'approved') {
      entries.push({ action: 'approved', description: `${p} gave <strong>final approval</strong> — form is now <strong>Approved</strong>` });
    } else if (body.status === 'rejected') {
      const reason = body.rejection_reason ? `: ${body.rejection_reason}` : '';
      entries.push({ action: 'rejected', description: `${p} <strong>permanently rejected</strong> the submission${reason}` });
    } else if (WORKFLOW_STATUS_LABELS[body.status]) {
      entries.push({ action: 'status-changed', description: `${p} changed status from <strong>${oldStatusLabel}</strong> to <strong>${statusLabel}</strong>` });
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
        description: `${p} added line item: <strong>${item.description}</strong> - ${fmt(item.total)}${item.budget_code ? ' (Budget: ' + item.budget_code + ')' : ''}`
      });
    }

    // Removed items
    const removed = oldItems.filter(i => !newDescs.has(i.description));
    for (const item of removed) {
      entries.push({
        action: 'item-removed',
        description: `${p} removed line item: <strong>${item.description}</strong> - ${fmt(item.total)}`
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
   WORKFLOW ENGINE
   ======================================== */
const WORKFLOW_STEPS = [
  'secondary_3_review',
  'secondary_2_review',
  'secondary_1_review',
  'primary_review',
  'accounting_review',
  'ap_review',
  'approved',
];

const WORKFLOW_STATUS_LABELS = {
  'draft': 'Draft',
  'submitted': 'Submitted',
  'secondary_3_review': 'Secondary Approver 3 Review',
  'secondary_2_review': 'Secondary Approver 2 Review',
  'secondary_1_review': 'Secondary Approver 1 Review',
  'primary_review': 'Primary Approver Review',
  'accounting_review': 'Accounting Review',
  'ap_review': 'A/P Review',
  'approved': 'Approved',
  'rejected': 'Rejected',
  'accounting-review': 'Accounting Review',
  'ap-review': 'A/P Review',
};

const STEP_APPROVER_FIELD = {
  'secondary_3_review': 'secondary_approver_3',
  'secondary_2_review': 'secondary_approver_2',
  'secondary_1_review': 'secondary_approver_1',
  'primary_review': 'primary_approver',
};

async function getApprovalChain(env, restrictionGroupId) {
  const chain = [];

  if (restrictionGroupId) {
    const { results: groups } = await env.DB.prepare(
      'SELECT primary_approver, secondary_approver_1, secondary_approver_2, secondary_approver_3 FROM restriction_groups WHERE id = ?'
    ).bind(restrictionGroupId).all();

    if (groups.length) {
      const g = groups[0];
      const approverSteps = [
        { step: 'secondary_3_review', email: g.secondary_approver_3 },
        { step: 'secondary_2_review', email: g.secondary_approver_2 },
        { step: 'secondary_1_review', email: g.secondary_approver_1 },
        { step: 'primary_review', email: g.primary_approver },
      ];

      for (const s of approverSteps) {
        if (s.email) {
          const name = await getUserDisplayName(env, s.email);
          chain.push({ step: s.step, email: s.email.toLowerCase().trim(), name });
        }
      }
    }
  }

  chain.push({ step: 'accounting_review', email: null, name: null, role: 'accountant' });
  chain.push({ step: 'ap_review', email: null, name: null, role: 'accounts_payable' });

  return chain;
}

async function getUserDisplayName(env, email) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT user_first_name, user_last_name FROM user_data WHERE LOWER(user_email) = ?'
    ).bind(email.toLowerCase().trim()).all();
    if (results.length) {
      return ((results[0].user_first_name || '') + ' ' + (results[0].user_last_name || '')).trim() || email;
    }
  } catch (e) {}
  return email;
}

async function roundRobinAssign(env, role, stepStatus) {
  const { results: users } = await env.DB.prepare(
    'SELECT user_email, user_first_name, user_last_name, user_roles FROM user_data WHERE status = ? OR status IS NULL'
  ).bind('active').all();

  const eligible = users.filter(u => {
    try {
      const roles = JSON.parse(u.user_roles || '[]');
      return roles.includes(role);
    } catch (e) { return false; }
  });

  if (!eligible.length) return null;

  const placeholders = eligible.map(() => '?').join(',');
  const emails = eligible.map(u => u.user_email.toLowerCase());

  let counts = {};
  try {
    const { results: countRows } = await env.DB.prepare(
      `SELECT LOWER(assigned_to_email) as email, COUNT(*) as cnt FROM dashboard_data
       WHERE status = ? AND LOWER(assigned_to_email) IN (${placeholders}) AND deleted_at IS NULL
       GROUP BY LOWER(assigned_to_email)`
    ).bind(stepStatus, ...emails).all();

    for (const row of countRows) {
      counts[row.email] = row.cnt;
    }
  } catch (e) {}

  eligible.sort((a, b) => {
    const countA = counts[a.user_email.toLowerCase()] || 0;
    const countB = counts[b.user_email.toLowerCase()] || 0;
    if (countA !== countB) return countA - countB;
    return a.user_email.localeCompare(b.user_email);
  });

  const chosen = eligible[0];
  const name = ((chosen.user_first_name || '') + ' ' + (chosen.user_last_name || '')).trim() || chosen.user_email;
  return { email: chosen.user_email.toLowerCase(), name };
}

async function advanceToNextStep(env, rfpNumber, currentStatus, restrictionGroupId) {
  const chain = await getApprovalChain(env, restrictionGroupId);

  let startIdx = -1;
  if (currentStatus === 'submitted') {
    startIdx = -1;
  } else {
    startIdx = chain.findIndex(c => c.step === currentStatus);
  }

  for (let i = startIdx + 1; i < chain.length; i++) {
    const step = chain[i];

    if (step.step === 'approved') {
      return { status: 'approved', assignedToEmail: null, assignedToName: null };
    }

    if (step.role) {
      const assigned = await roundRobinAssign(env, step.role, step.step);
      if (assigned) {
        return { status: step.step, assignedToEmail: assigned.email, assignedToName: assigned.name };
      }
      continue;
    }

    if (step.email) {
      return { status: step.step, assignedToEmail: step.email, assignedToName: step.name };
    }
  }

  return { status: 'approved', assignedToEmail: null, assignedToName: null };
}


/* ========================================
   WORKFLOW – APPROVE / REJECT / RETURN
   ======================================== */
async function handleWorkflowAction(rfpNumber, request, env) {
  const body = await request.json();
  const action = body.action;
  const performerEmail = (body.performer_email || '').toLowerCase().trim();
  const performerName = body.performer_name || 'Unknown';
  const rejectionReason = body.reason || '';
  const returnToStep = body.return_to_step || null;
  const apBatchNumber = body.ap_batch || null;

  if (!action || !performerEmail) {
    return json({ error: 'action and performer_email are required' }, 400);
  }

  const { results: rows } = await env.DB.prepare(
    'SELECT * FROM dashboard_data WHERE rfp_number = ? AND deleted_at IS NULL'
  ).bind(rfpNumber).all();

  if (!rows.length) return json({ error: 'RFP not found' }, 404);
  const rfp = rows[0];

  let performerRoles = [];
  let performerUserId = null;
  try {
    const { results: pUser } = await env.DB.prepare(
      'SELECT user_id, user_roles FROM user_data WHERE LOWER(user_email) = ?'
    ).bind(performerEmail).all();
    if (pUser.length) {
      performerUserId = 'E' + pUser[0].user_id;
      performerRoles = JSON.parse(pUser[0].user_roles || '["user"]');
    }
  } catch (e) {}

  const isAdmin = performerRoles.includes('super_user') || performerRoles.includes('admin');
  const isAssigned = (rfp.assigned_to_email || '').toLowerCase() === performerEmail;
  const isAccountant = performerRoles.includes('accountant');
  const isAP = performerRoles.includes('accounts_payable');
  const atAccountingStep = rfp.status === 'accounting_review' || rfp.status === 'accounting-review';
  const atAPStep = rfp.status === 'ap_review' || rfp.status === 'ap-review';

  if (!isAdmin && !isAssigned && !(isAccountant && atAccountingStep) && !(isAP && atAPStep)) {
    return json({ error: 'You do not have permission to perform this action on this form' }, 403);
  }

  const submitterId = (rfp.submitter_id || '').toUpperCase();
  if (performerUserId && performerUserId === submitterId && action !== 'return') {
    return json({ error: 'You cannot approve or reject your own submission' }, 403);
  }

  const now = new Date().toISOString();
  const restrictionGroupId = rfp.restriction_group_id;
  let history = [];
  try { history = JSON.parse(rfp.approval_history || '[]'); } catch (e) { history = []; }

  const p = `<strong>${performerName}</strong>`;
  const stepLabel = WORKFLOW_STATUS_LABELS[rfp.status] || rfp.status;

  // ── APPROVE ──
  if (action === 'approve') {
    history.push({
      step: rfp.status,
      email: performerEmail,
      name: performerName,
      action: 'approved',
      at: now,
    });

    if ((rfp.status === 'ap_review' || rfp.status === 'ap-review') && !apBatchNumber) {
      return json({ error: 'Batch number is required for A/P approval' }, 400);
    }

    const next = await advanceToNextStep(env, rfpNumber, rfp.status, restrictionGroupId);

    const updates = {
      status: next.status,
      assigned_to: next.assignedToName || null,
      assigned_to_email: next.assignedToEmail || null,
      approval_history: JSON.stringify(history),
    };

    if (apBatchNumber) {
      updates.ap_batch = apBatchNumber;
    }

    const setClauses = Object.keys(updates).map(k => `${k} = ?`);
    const setValues = Object.values(updates);

    await env.DB.prepare(
      `UPDATE dashboard_data SET ${setClauses.join(', ')} WHERE rfp_number = ?`
    ).bind(...setValues, rfpNumber).run();

    const nextLabel = WORKFLOW_STATUS_LABELS[next.status] || next.status;
    let auditDesc = `${p} <strong>approved</strong> at <strong>${stepLabel}</strong>`;
    if (next.status === 'approved') {
      auditDesc += ' — form is now <strong>Approved</strong>';
      if (apBatchNumber) auditDesc += ` (Batch: ${apBatchNumber})`;
    } else {
      auditDesc += ` — routed to <strong>${next.assignedToName || 'Unknown'}</strong> for <strong>${nextLabel}</strong>`;
    }

    await env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(rfpNumber, 'approved', auditDesc, performerName, performerEmail, now).run();

    return json({ rfp_number: rfpNumber, new_status: next.status, assigned_to: next.assignedToName, message: 'Approved' });
  }

  // ── REJECT (permanent) ──
  if (action === 'reject') {
    history.push({
      step: rfp.status,
      email: performerEmail,
      name: performerName,
      action: 'rejected',
      reason: rejectionReason,
      at: now,
    });

    await env.DB.prepare(
      'UPDATE dashboard_data SET status = ?, assigned_to = NULL, assigned_to_email = NULL, approval_history = ? WHERE rfp_number = ?'
    ).bind('rejected', JSON.stringify(history), rfpNumber).run();

    let auditDesc = `${p} <strong>permanently rejected</strong> the submission at <strong>${stepLabel}</strong>`;
    if (rejectionReason) auditDesc += ` — Reason: ${rejectionReason}`;

    await env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(rfpNumber, 'rejected', auditDesc, performerName, performerEmail, now).run();

    return json({ rfp_number: rfpNumber, new_status: 'rejected', message: 'Rejected' });
  }

  // ── RETURN (to a prior step) ──
  if (action === 'return') {
    if (!returnToStep) {
      return json({ error: 'return_to_step is required' }, 400);
    }

    if (!isAdmin) {
      const completedSteps = history.map(h => h.step);
      if (!completedSteps.includes(returnToStep) && returnToStep !== 'submitted') {
        return json({ error: 'Can only return to a step the form has already completed' }, 400);
      }
    }

    let returnAssignee = null;

    if (returnToStep === 'submitted' || returnToStep === 'draft') {
      try {
        const subId = (rfp.submitter_id || '').replace(/^E/, '');
        const { results: subUser } = await env.DB.prepare(
          'SELECT user_email, user_first_name, user_last_name FROM user_data WHERE user_id = ?'
        ).bind(subId).all();
        if (subUser.length) {
          returnAssignee = {
            email: subUser[0].user_email.toLowerCase(),
            name: ((subUser[0].user_first_name || '') + ' ' + (subUser[0].user_last_name || '')).trim() || subUser[0].user_email,
          };
        }
      } catch (e) {}
    } else if (STEP_APPROVER_FIELD[returnToStep] && restrictionGroupId) {
      try {
        const field = STEP_APPROVER_FIELD[returnToStep];
        const { results: groups } = await env.DB.prepare(
          `SELECT ${field} FROM restriction_groups WHERE id = ?`
        ).bind(restrictionGroupId).all();
        if (groups.length && groups[0][field]) {
          const email = groups[0][field].toLowerCase().trim();
          const name = await getUserDisplayName(env, email);
          returnAssignee = { email, name };
        }
      } catch (e) {}
    } else if (returnToStep === 'accounting_review') {
      returnAssignee = await roundRobinAssign(env, 'accountant', 'accounting_review');
    } else if (returnToStep === 'ap_review') {
      returnAssignee = await roundRobinAssign(env, 'accounts_payable', 'ap_review');
    }

    history.push({
      step: rfp.status,
      email: performerEmail,
      name: performerName,
      action: 'returned',
      return_to: returnToStep,
      reason: rejectionReason,
      at: now,
    });

    await env.DB.prepare(
      'UPDATE dashboard_data SET status = ?, assigned_to = ?, assigned_to_email = ?, approval_history = ? WHERE rfp_number = ?'
    ).bind(
      returnToStep,
      returnAssignee ? returnAssignee.name : null,
      returnAssignee ? returnAssignee.email : null,
      JSON.stringify(history),
      rfpNumber
    ).run();

    const returnLabel = WORKFLOW_STATUS_LABELS[returnToStep] || returnToStep;
    let auditDesc = `${p} <strong>returned</strong> the form from <strong>${stepLabel}</strong> to <strong>${returnLabel}</strong>`;
    if (returnAssignee) auditDesc += ` (assigned to ${returnAssignee.name})`;
    if (rejectionReason) auditDesc += ` — Reason: ${rejectionReason}`;

    await env.DB.prepare(
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(rfpNumber, 'returned', auditDesc, performerName, performerEmail, now).run();

    return json({ rfp_number: rfpNumber, new_status: returnToStep, assigned_to: returnAssignee?.name, message: 'Returned' });
  }

  return json({ error: 'Invalid action. Use: approve, reject, return' }, 400);
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
            rfp_number, submitter_name, submitter_id, user_email, budget_approver,
            submission_date, request_type, vendor_name, vendor_number,
            vendor_address, invoice_number, employee_name, employee_id,
            description, status, assigned_to, ap_batch, mileage_total, creation_source, check_number
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          currentRfp,
          sub.name,
          sub.id,
          (sub.email || '').toLowerCase(),
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
    'ALTER TABLE user_data ADD COLUMN preferences TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN assigned_to_email TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN approval_history TEXT',
    'ALTER TABLE dashboard_data ADD COLUMN restriction_group_id INTEGER',
    'ALTER TABLE audit_logs ADD COLUMN performed_by_email TEXT',
    'ALTER TABLE user_restriction_assignments ADD COLUMN name TEXT',
    'ALTER TABLE user_data DROP COLUMN restrictions',
    'ALTER TABLE dashboard_data ADD COLUMN user_email TEXT',
    `CREATE TABLE IF NOT EXISTS rfp_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rfp_number INTEGER NOT NULL,
      note_text TEXT NOT NULL,
      author_name TEXT,
      author_email TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (rfp_number) REFERENCES dashboard_data(rfp_number)
    )`,
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
    `CREATE TABLE IF NOT EXISTS ap_batch (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ap_batch_type TEXT NOT NULL,
      ap_batch_number TEXT NOT NULL UNIQUE
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

  // Backfill name on user_restriction_assignments from restriction_groups
  try {
    await env.DB.prepare(`
      UPDATE user_restriction_assignments SET name = (
        SELECT restriction_groups.name FROM restriction_groups WHERE restriction_groups.id = user_restriction_assignments.group_id
      ) WHERE name IS NULL
    `).run();
    results.push({ sql: 'BACKFILL user_restriction_assignments.name', status: 'applied' });
  } catch (e) {
    results.push({ sql: 'BACKFILL user_restriction_assignments.name', status: 'skipped', reason: e.message });
  }

  // Backfill user_email on dashboard_data from user_data via submitter_id
  try {
    await env.DB.prepare(`
      UPDATE dashboard_data SET user_email = LOWER(u.user_email)
      FROM user_data u
      WHERE dashboard_data.user_email IS NULL
        AND dashboard_data.submitter_id IS NOT NULL
        AND (UPPER(dashboard_data.submitter_id) = 'E' || u.user_id OR dashboard_data.submitter_id = CAST(u.user_id AS TEXT))
    `).run();
    results.push({ sql: 'BACKFILL dashboard_data.user_email', status: 'applied' });
  } catch (e) {
    results.push({ sql: 'BACKFILL dashboard_data.user_email', status: 'skipped', reason: e.message });
  }

  // Backfill dashboard_data.description → rfp_notes for existing RFPs
  try {
    await env.DB.prepare(`
      INSERT INTO rfp_notes (rfp_number, note_text, author_name, author_email, created_at)
      SELECT d.rfp_number, d.description, d.submitter_name, d.user_email,
        COALESCE(d.submission_date, datetime('now'))
      FROM dashboard_data d
      WHERE d.description IS NOT NULL AND d.description != ''
        AND d.rfp_number NOT IN (SELECT DISTINCT rfp_number FROM rfp_notes)
    `).run();
    results.push({ sql: 'BACKFILL rfp_notes from description', status: 'applied' });
  } catch (e) {
    results.push({ sql: 'BACKFILL rfp_notes from description', status: 'skipped', reason: e.message });
  }

  // Seed ap_batch table with Wednesday batch numbers for 2026
  try {
    const { results: existing } = await env.DB.prepare('SELECT COUNT(*) as cnt FROM ap_batch').all();
    if (existing[0].cnt === 0) {
      // Generate all Wednesdays of 2026
      const batches = [];
      const d = new Date(2026, 0, 1); // Jan 1 2026
      // Find first Wednesday
      while (d.getDay() !== 3) d.setDate(d.getDate() + 1);
      while (d.getFullYear() === 2026) {
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        const yy = String(d.getFullYear()).slice(-2);
        batches.push({ vendor: `${mm}${dd}${yy}A1`, employee: `${mm}${dd}${yy}E1` });
        d.setDate(d.getDate() + 7);
      }
      for (const b of batches) {
        await env.DB.prepare('INSERT OR IGNORE INTO ap_batch (ap_batch_type, ap_batch_number) VALUES (?, ?)').bind('vendor_payment', b.vendor).run();
        await env.DB.prepare('INSERT OR IGNORE INTO ap_batch (ap_batch_type, ap_batch_number) VALUES (?, ?)').bind('employee_reimbursement', b.employee).run();
      }
      results.push({ sql: 'SEED ap_batch (Wednesdays 2026)', status: 'applied', count: batches.length * 2 });
    } else {
      results.push({ sql: 'SEED ap_batch', status: 'skipped', reason: `already has ${existing[0].cnt} rows` });
    }
  } catch (e) {
    results.push({ sql: 'SEED ap_batch', status: 'error', reason: e.message });
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

// Backfill form_data: parse budget_code into fund/org/program/finance/course columns
async function handleMigrateFormDataSegments(env) {
  const { results: rows } = await env.DB.prepare(
    "SELECT rowid, budget_code FROM form_data WHERE budget_code IS NOT NULL AND (fund IS NULL OR fund = '')"
  ).all();

  let updated = 0, skipped = 0;
  const batches = [];
  let batch = [];

  for (const row of rows) {
    const seg = parseBudgetSegments(row.budget_code);
    if (!seg.fund) { skipped++; continue; }

    batch.push(
      env.DB.prepare(
        'UPDATE form_data SET fund = ?, organization = ?, program = ?, finance = ? WHERE rowid = ?'
      ).bind(seg.fund, seg.organization, seg.program, seg.finance, row.rowid)
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

  return json({ message: `Backfilled form_data segments (2+3+3+3+3 format)`, updated, skipped, total: rows.length });
}


/* ========================================
   AUDIT LOGS
   ======================================== */
async function handleGetAuditLogs(rfpNumber, env) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM audit_logs WHERE rfp_number = ? ORDER BY performed_at ASC, id ASC'
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
      'INSERT INTO audit_logs (rfp_number, action, description, performed_by, performed_by_email, performed_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      rfpNumber,
      body.action || 'update',
      body.description || '',
      body.performed_by || 'Unknown',
      body.performed_by_email || null,
      new Date().toISOString(),
    ).run();
    return json({ message: 'Audit log created' }, 201);
  } catch (e) {
    return json({ error: 'Failed to create audit log', detail: e.message }, 500);
  }
}


/* ========================================
   NOTES – LIST & CREATE
   ======================================== */
async function handleGetNotes(rfpNumber, env) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT * FROM rfp_notes WHERE rfp_number = ? ORDER BY created_at ASC'
    ).bind(rfpNumber).all();
    return json({ notes: results });
  } catch (e) {
    return json({ notes: [], error: e.message });
  }
}

async function handleCreateNote(rfpNumber, request, env) {
  const body = await request.json();
  if (!body.note_text || !body.note_text.trim()) {
    return json({ error: 'note_text is required' }, 400);
  }
  try {
    const { results } = await env.DB.prepare(
      'INSERT INTO rfp_notes (rfp_number, note_text, author_name, author_email, created_at) VALUES (?, ?, ?, ?, ?) RETURNING *'
    ).bind(
      rfpNumber,
      body.note_text.trim(),
      body.author_name || 'Unknown',
      (body.author_email || '').toLowerCase().trim(),
      new Date().toISOString()
    ).all();
    return json({ note: results[0] }, 201);
  } catch (e) {
    return json({ error: 'Failed to create note', detail: e.message }, 500);
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
    'SELECT user_id, user_first_name, user_last_name, user_email, phone_number, department, title, profile_picture_key, status, user_roles FROM user_data ORDER BY user_first_name ASC'
  ).all();

  // Fetch all restriction group assignments
  let assignMap = {};
  try {
    const { results: assignments } = await env.DB.prepare(
      'SELECT user_email, group_id FROM user_restriction_assignments'
    ).all();
    for (const a of assignments) {
      const e = (a.user_email || '').toLowerCase();
      if (!assignMap[e]) assignMap[e] = [];
      assignMap[e].push(a.group_id);
    }
  } catch (e) {}

  const merged = users.map(u => {
    let roles = [];
    try { roles = JSON.parse(u.user_roles || '["user"]'); } catch (e) { roles = ['user']; }
    const isSuperUser = roles.includes('super_user');
    const isAdmin = roles.includes('admin') || isSuperUser;
    const emailLower = (u.user_email || '').toLowerCase();
    return {
      user_id: u.user_id,
      first_name: u.user_first_name,
      last_name: u.user_last_name,
      email: u.user_email,
      phone_number: u.phone_number || '',
      department: u.department || '',
      title: u.title || '',
      profile_picture_key: u.profile_picture_key || null,
      status: u.status || 'active',
      roles,
      restriction_group_ids: assignMap[emailLower] || [],
      permissions: {
        can_manage_users: isSuperUser,
        can_manage_vendors: isAdmin,
        can_approve: isAdmin,
        can_reject: isAdmin,
        can_assign: isAdmin,
        can_view_all: isAdmin,
        can_export: isAdmin,
        can_import: isAdmin,
      },
    };
  });

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
   ROLE DEFINITIONS
   ======================================== */
async function handleGetRoleDefinitions(env) {
  const allRoles = ['super_user', 'admin', 'accountant', 'accounts_payable', 'submitter', 'user'];

  // Also gather any custom roles from user_data
  try {
    const { results } = await env.DB.prepare(
      'SELECT DISTINCT user_roles FROM user_data WHERE user_roles IS NOT NULL'
    ).all();
    for (const row of results) {
      try {
        const parsed = JSON.parse(row.user_roles || '[]');
        for (const r of parsed) {
          if (!allRoles.includes(r)) allRoles.push(r);
        }
      } catch (e) {}
    }
  } catch (e) {}

  return json({
    roles: allRoles.map(r => ({
      role_name: r,
      label: r.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '),
    }))
  });
}


/* ========================================
   USER ROLES – UPDATE
   ======================================== */
async function handleUpdateUserRoles(request, env) {
  const body = await request.json();
  const { email, roles } = body;

  if (!email || !Array.isArray(roles)) {
    return json({ error: 'email and roles array are required' }, 400);
  }

  try {
    await env.DB.prepare(
      'UPDATE user_data SET user_roles = ? WHERE LOWER(user_email) = ?'
    ).bind(JSON.stringify(roles), email.toLowerCase().trim()).run();

    return json({ message: 'Roles updated', email, roles });
  } catch (e) {
    return json({ error: 'Failed to update roles: ' + e.message }, 500);
  }
}

async function handleGetUserRestrictionRules(url, env) {
  const email = (url.searchParams.get('email') || '').toLowerCase().trim();
  if (!email) return json({ restricted_budget: false, restricted_vendors: false, budget_rules: [], vendor_numbers: [], groups: [] });

  try {
    const { results: assignments } = await env.DB.prepare(
      'SELECT group_id, name FROM user_restriction_assignments WHERE LOWER(user_email) = ?'
    ).bind(email).all();

    if (!assignments.length) {
      return json({ restricted_budget: false, restricted_vendors: false, budget_rules: [], vendor_numbers: [], groups: [] });
    }

    const groupIds = assignments.map(a => a.group_id);
    const placeholders = groupIds.map(() => '?').join(',');

    const { results: rules } = await env.DB.prepare(
      `SELECT group_id, fund, organization, program, finance, course FROM restriction_group_budget_rules WHERE group_id IN (${placeholders})`
    ).bind(...groupIds).all();

    const { results: vendors } = await env.DB.prepare(
      `SELECT group_id, vendor_number FROM restriction_group_vendors WHERE group_id IN (${placeholders})`
    ).bind(...groupIds).all();

    // Build per-group data
    const groups = assignments.map(a => {
      const groupRules = rules.filter(r => r.group_id === a.group_id).map(r => ({
        fund: r.fund, organization: r.organization, program: r.program, finance: r.finance, course: r.course
      }));
      const groupVendors = vendors.filter(v => v.group_id === a.group_id).map(v => v.vendor_number);
      return {
        id: a.group_id,
        name: a.name || null,
        budget_rules: groupRules,
        vendor_numbers: groupVendors
      };
    });

    // Flat lists for backwards compatibility
    const allRules = rules.map(r => ({ fund: r.fund, organization: r.organization, program: r.program, finance: r.finance, course: r.course }));
    const allVendorNumbers = [...new Set(vendors.map(v => v.vendor_number))];

    // A group with budget rules but NO vendor restrictions means "any vendor" for those codes
    const hasUnrestrictedGroup = groups.some(g => g.budget_rules.length > 0 && g.vendor_numbers.length === 0);

    return json({
      restricted_budget: allRules.length > 0,
      restricted_vendors: allVendorNumbers.length > 0 && !hasUnrestrictedGroup,
      budget_rules: allRules,
      vendor_numbers: allVendorNumbers,
      groups: groups,
      has_unrestricted_group: hasUnrestrictedGroup
    });
  } catch (e) {
    return json({ restricted_budget: false, restricted_vendors: false, budget_rules: [], vendor_numbers: [], groups: [], error: e.message });
  }
}

async function handleUpdateUserRestrictionGroups(request, env) {
  const body = await request.json();
  const { email, group_ids } = body;

  if (!email || !Array.isArray(group_ids)) {
    return json({ error: 'email and group_ids array are required' }, 400);
  }

  const emailLower = email.toLowerCase().trim();

  try {
    // Delete existing assignments for this user
    await env.DB.prepare(
      'DELETE FROM user_restriction_assignments WHERE LOWER(user_email) = ?'
    ).bind(emailLower).run();

    // Insert new assignments (with group name)
    if (group_ids.length > 0) {
      // Look up group names
      const placeholders = group_ids.map(() => '?').join(',');
      const { results: groups } = await env.DB.prepare(
        `SELECT id, name FROM restriction_groups WHERE id IN (${placeholders})`
      ).bind(...group_ids).all();
      const nameMap = {};
      for (const g of groups) nameMap[g.id] = g.name;

      const stmts = group_ids.map(gid =>
        env.DB.prepare(
          'INSERT INTO user_restriction_assignments (user_email, group_id, name) VALUES (?, ?, ?)'
        ).bind(emailLower, gid, nameMap[gid] || null)
      );
      await env.DB.batch(stmts);
    }

    return json({ message: 'Restriction groups updated', email: emailLower, group_ids });
  } catch (e) {
    return json({ error: 'Failed to update restriction groups: ' + e.message }, 500);
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


/* ========================================
   RESTRICTION GROUPS
   ======================================== */
async function handleListRestrictionGroups(env) {
  try {
    const { results: groups } = await env.DB.prepare(
      'SELECT * FROM restriction_groups ORDER BY name ASC'
    ).all();

    // Fetch all budget rules, vendors, and assignments in bulk
    const { results: allRules } = await env.DB.prepare(
      'SELECT * FROM restriction_group_budget_rules ORDER BY id'
    ).all();
    const { results: allVendors } = await env.DB.prepare(
      'SELECT * FROM restriction_group_vendors'
    ).all();

    let allAssignments = [];
    try {
      const { results: assignments } = await env.DB.prepare(
        'SELECT * FROM user_restriction_assignments'
      ).all();
      allAssignments = assignments;
    } catch (e) {}

    // Build lookup maps
    const rulesMap = {};
    for (const r of allRules) {
      if (!rulesMap[r.group_id]) rulesMap[r.group_id] = [];
      rulesMap[r.group_id].push(r);
    }
    const vendorsMap = {};
    for (const v of allVendors) {
      if (!vendorsMap[v.group_id]) vendorsMap[v.group_id] = [];
      vendorsMap[v.group_id].push(v.vendor_number);
    }
    const assignMap = {};
    for (const a of allAssignments) {
      if (!assignMap[a.group_id]) assignMap[a.group_id] = [];
      assignMap[a.group_id].push(a.user_email);
    }

    const enriched = groups.map(g => ({
      ...g,
      budget_rules: rulesMap[g.id] || [],
      vendors: vendorsMap[g.id] || [],
      assigned_users: assignMap[g.id] || [],
    }));

    return json({ groups: enriched });
  } catch (e) {
    return json({ error: 'Failed to load restriction groups: ' + e.message }, 500);
  }
}

async function handleCreateRestrictionGroup(request, env) {
  const body = await request.json();
  const { name, description } = body;
  if (!name) return json({ error: 'Name is required' }, 400);

  try {
    const result = await env.DB.prepare(
      'INSERT INTO restriction_groups (name, description, created_at) VALUES (?, ?, datetime(\'now\'))'
    ).bind(name, description || '').run();

    const id = result.meta?.last_row_id;
    return json({ id, name, description: description || '' }, 201);
  } catch (e) {
    return json({ error: 'Failed to create group: ' + e.message }, 500);
  }
}

async function handleUpdateRestrictionGroup(id, request, env) {
  const body = await request.json();
  const { name, description } = body;
  if (!name) return json({ error: 'Name is required' }, 400);

  try {
    await env.DB.prepare(
      'UPDATE restriction_groups SET name = ?, description = ? WHERE id = ?'
    ).bind(name, description || '', id).run();
    // Keep junction table name in sync
    await env.DB.prepare(
      'UPDATE user_restriction_assignments SET name = ? WHERE group_id = ?'
    ).bind(name, id).run();
    return json({ message: 'Updated', id });
  } catch (e) {
    return json({ error: 'Failed to update: ' + e.message }, 500);
  }
}

async function handleDeleteRestrictionGroup(id, env) {
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM restriction_group_budget_rules WHERE group_id = ?').bind(id),
      env.DB.prepare('DELETE FROM restriction_group_vendors WHERE group_id = ?').bind(id),
      env.DB.prepare('DELETE FROM user_restriction_assignments WHERE group_id = ?').bind(id),
      env.DB.prepare('DELETE FROM restriction_groups WHERE id = ?').bind(id),
    ]);
    return json({ message: 'Deleted' });
  } catch (e) {
    return json({ error: 'Failed to delete: ' + e.message }, 500);
  }
}

async function handleUpdateRgApprovers(id, request, env) {
  const body = await request.json();
  try {
    await env.DB.prepare(
      'UPDATE restriction_groups SET primary_approver = ?, secondary_approver_1 = ?, secondary_approver_2 = ?, secondary_approver_3 = ? WHERE id = ?'
    ).bind(
      body.primary_approver || null,
      body.secondary_approver_1 || null,
      body.secondary_approver_2 || null,
      body.secondary_approver_3 || null,
      id
    ).run();
    return json({ message: 'Approvers updated' });
  } catch (e) {
    return json({ error: 'Failed to update approvers: ' + e.message }, 500);
  }
}

async function handleAddRgBudgetRule(groupId, request, env) {
  const body = await request.json();
  try {
    const result = await env.DB.prepare(
      'INSERT INTO restriction_group_budget_rules (group_id, fund, organization, program, finance, course) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(groupId, body.fund || '', body.organization || '', body.program || '', body.finance || '', body.course || '').run();
    return json({ id: result.meta?.last_row_id }, 201);
  } catch (e) {
    return json({ error: 'Failed to add rule: ' + e.message }, 500);
  }
}

async function handleDeleteRgBudgetRule(groupId, ruleId, env) {
  try {
    await env.DB.prepare(
      'DELETE FROM restriction_group_budget_rules WHERE id = ? AND group_id = ?'
    ).bind(ruleId, groupId).run();
    return json({ message: 'Rule deleted' });
  } catch (e) {
    return json({ error: 'Failed to delete rule: ' + e.message }, 500);
  }
}

async function handleAddRgVendors(groupId, request, env) {
  const body = await request.json();
  const vendors = body.vendor_numbers || [];
  if (!vendors.length) return json({ error: 'No vendors provided' }, 400);

  try {
    const stmts = vendors.map(v =>
      env.DB.prepare('INSERT OR IGNORE INTO restriction_group_vendors (group_id, vendor_number) VALUES (?, ?)').bind(groupId, v)
    );
    await env.DB.batch(stmts);
    return json({ message: 'Vendors added', count: vendors.length });
  } catch (e) {
    return json({ error: 'Failed to add vendors: ' + e.message }, 500);
  }
}

async function handleDeleteRgVendor(groupId, vendorNumber, env) {
  try {
    await env.DB.prepare(
      'DELETE FROM restriction_group_vendors WHERE group_id = ? AND vendor_number = ?'
    ).bind(groupId, vendorNumber).run();
    return json({ message: 'Vendor removed' });
  } catch (e) {
    return json({ error: 'Failed to remove vendor: ' + e.message }, 500);
  }
}
