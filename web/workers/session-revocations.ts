import { DurableObject } from "cloudflare:workers";

/**
 * One object per signed-out console session (named `session:<sid>`). It
 * remembers the revocation until the session would have expired, then an
 * alarm deletes it, so storage never grows past the live sessions.
 */
export class SessionRevocations extends DurableObject<Env> {
  async revoke(expiresAt: number): Promise<void> {
    await this.ctx.storage.put("revoked_until", expiresAt);
    await this.ctx.storage.setAlarm(Math.max(Date.now(), expiresAt));
  }

  async isRevoked(): Promise<boolean> {
    const until = await this.ctx.storage.get<number>("revoked_until");
    return until !== undefined;
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
