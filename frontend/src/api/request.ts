export class RequestError extends Error {
  status: number;
  outcome: "unknown" | "auth" | "rejected";
  constructor(
    message: string,
    status: number,
    outcome: "unknown" | "auth" | "rejected",
  ) {
    super(message);
    this.status = status;
    this.outcome = outcome;
  }
}

export type Pending = Readonly<{
  endpoint: "/admin/actions" | "/admin/invites" | "/admin/replicas/reconcile";
  body: string;
  key?: string;
  label: string;
  subject: "administrator:1";
}>;

export function prepare(
  endpoint: "/admin/actions" | "/admin/invites",
  payload: object,
  label: string,
): Pending {
  const body = JSON.stringify(payload);
  if (new TextEncoder().encode(body).length > 4096)
    throw new Error("Request exceeds the 4096-byte limit.");
  return Object.freeze({
    endpoint,
    body,
    key: crypto.randomUUID(),
    label,
    subject: "administrator:1",
  });
}

export async function request(
  path: string,
  body?: string,
  key?: string,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers:
        body === undefined
          ? {}
          : {
              "Content-Type": "application/json",
              ...(key ? { "Idempotency-Key": key } : {}),
            },
      body,
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new RequestError(
      "No confirmed response. The operation may have committed.",
      0,
      "unknown",
    );
  }
  if (!response.ok) {
    // Do not echo server text: an error body could contain sensitive request data.
    throw new RequestError(
      response.status === 401
        ? "Sign in again to continue."
        : response.status === 503
          ? "Controller unavailable; outcome is unknown."
          : `Request returned HTTP ${response.status}.`,
      response.status,
      response.status === 401
        ? "auth"
        : response.status >= 500
          ? "unknown"
          : "rejected",
    );
  }
  if (response.status === 204) return null;
  try {
    return await response.json();
  } catch {
    throw new RequestError(
      "Response could not be read; outcome is unknown.",
      response.status,
      "unknown",
    );
  }
}

export async function send(pending: Pending) {
  const result = (await request(
    pending.endpoint,
    pending.body,
    pending.key,
  )) as Record<string, unknown> | null;
  if (pending.endpoint === "/admin/replicas/reconcile") {
    if (
      !result ||
      result.committed !== true ||
      result.semantics !== "durable request receipt; not lease renewal" ||
      !["roster_revision", "issued_at_ms", "expires_at_ms"].every(
        (k) => Number.isSafeInteger(result[k]) && (result[k] as number) >= 0,
      )
    ) {
      throw new RequestError(
        "Unrecognized serving receipt; outcome is unknown. Retry the identical body/ID.",
        200,
        "unknown",
      );
    }
    return result;
  }
  const topology =
    pending.endpoint === "/admin/actions" &&
    [
      "add_membership",
      "remove_membership",
      "delete_mesh",
      "delete_node",
      "remove_tunnel_intent",
    ].includes(JSON.parse(pending.body).action);
  if (
    !result ||
    (pending.endpoint === "/admin/invites"
      ? result.success !== true ||
        typeof result.invite_code !== "string" ||
        !result.invite_code
      : result.committed !== true ||
        (topology &&
          (result.convergence !== "polling" ||
            !Array.isArray(result.affected_nodes) ||
            !result.affected_nodes.every(
              (id) => Number.isSafeInteger(id) && id > 0,
            ))))
  ) {
    throw new RequestError(
      "Unrecognized confirmation; outcome is unknown.",
      200,
      "unknown",
    );
  }
  return result;
}
