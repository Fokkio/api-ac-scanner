"""Severity model: OWASP API Top 10 risk rating (primary) + CVSS (secondary)."""

# OWASP API Security Top 10 (2023) risk categories we detect
OWASP_API = {
    "API1:2023": "Broken Object Level Authorization (BOLA)",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization (BFLA)",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
    "A08:2021": "Software and Data Integrity Failures (Mass Assignment)",
}

# Qualitative severity derived from CVSS score
def cvss_to_level(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Info"


# Color tokens for the dashboard (anti-slop: muted, deliberate palette)
SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#27ae60",
    "Info": "#7f8c8d",
}

# Fix guidance templates keyed by rule id
FIX_GUIDANCE = {
    "nodejs-bola-object": (
        "Enforce ownership in the data layer. After loading the object, verify "
        "object.owner_id === req.user.id (or req.user.role === 'admin') before "
        "returning it. Prefer a scoped query such as "
        "Model.findOne({ _id, owner: req.user.id })."
    ),
    "nodejs-mass-assignment": (
        "Never pass req.body straight to the model. Use an explicit allowlist: "
        "const data = _.pick(req.body, ['name','email']); "
        "Model.update(data). Add schema validation (zod/Joi) and never allow "
        "role/isAdmin to be client-set."
    ),
    "python-bola-object": (
        "Scope the query to the current user: "
        "Model.query.filter_by(id=oid, owner_id=current_user.id).first(). "
        "Reject with 404 if not found. Add an ownership check helper and unit test."
    ),
    "python-mass-assignment": (
        "Use an explicit schema with load_only/only allowlist, e.g. "
        "Schema(only=('name','email')).load(request.get_json()). "
        "Never pass request.get_json() directly into Model(**data)."
    ),
    "php-bola-object": (
        "Verify ownership before use: load the row, then "
        "if ($row->owner_id !== $user->id) abort(403). Scope the query: "
        "Model::where('id', $id)->where('owner_id', $user->id)->first()."
    ),
    "php-mass-assignment": (
        "Use an explicit allowlist: $model->fill($request->only(['name','email'])); "
        "Never pass $request->all() to fill/create."
    ),
    "java-bola-object": (
        "Add an authorization check: "
        "if (!securityService.authorize(currentUser, object)) throw new ForbiddenException(); "
        "Prefer repository methods that scope by tenant/owner."
    ),
    "java-mass-assignment": (
        "Map request bodies through a DTO with explicit field mapping; never "
        "bind raw request JSON onto an entity. Use a DtoMapper.toEntity() allowlist."
    ),
    "nodejs-bfla-missing-guard": (
        "Add a function-level authorization guard at the top of the handler: "
        "if (req.user?.role !== 'admin') return res.status(403).json({error:'forbidden'}); "
        "Use middleware/guards (e.g. requireAdmin) on sensitive routes."
    ),
    "nodejs-no-rate-limit": (
        "Apply a rate limiter to the route: "
        "app.post('/login', rateLimit({windowMs:15*60*1000, max:10}), handler); "
        "Use express-rate-limit / slow-down on auth and state-changing endpoints."
    ),
    "python-bfla-missing-guard": (
        "Enforce a function-level admin/role check at the top of the handler: "
        "if not current_user.is_admin: abort(403). Use decorators like @require_admin."
    ),
    "python-no-rate-limit": (
        "Add Flask-Limiter to the route: @app.route(...); @limiter.limit('10/minute'). "
        "Apply limits on auth and mutation endpoints."
    ),
    "php-bfla-missing-guard": (
        "Add a role/ownership guard: if (!auth()->user()->isAdmin) abort(403); "
        "Use Gate/Policy or middleware on admin routes."
    ),
    "php-no-rate-limit": (
        "Apply a rate limiter: Laravel RateLimiter::attempt(...) or throttle:60,1 middleware "
        "on auth and mutation endpoints."
    ),
    "java-bfla-missing-guard": (
        "Enforce a function-level admin/role check: "
        "if (!securityService.authorize(getCurrentUser(), 'ADMIN')) throw new ForbiddenException();"
    ),
    "java-no-rate-limit": (
        "Add a rate limiter annotation/filter: @RateLimiter(name = 'api') or Bucket4j. "
        "Apply on auth and mutation endpoints."
    ),
}
