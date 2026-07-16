import { describe, expect, it } from "vitest";

import { PUBLIC_PRODUCT_COPY } from "../src/public-copy";

describe("public product copy", () => {
  it("uses PGID without claiming every PG72 service participates", () => {
    const copy = Object.values(PUBLIC_PRODUCT_COPY).join(" ");

    expect(copy).not.toContain("PG72 ID");
    expect(copy).not.toContain("所有服務");
    expect(PUBLIC_PRODUCT_COPY.aboutLead).toContain("支援 PGID 的服務");
    expect(PUBLIC_PRODUCT_COPY.aboutOverview).toContain("已接入 PGID 的服務");
  });

  it("states the invite, Passkey, and recovery boundaries", () => {
    expect(PUBLIC_PRODUCT_COPY.inviteAccess).toContain("邀請制 beta");
    expect(PUBLIC_PRODUCT_COPY.inviteAccess).toContain("不會取代邀請或自動建立帳號");
    expect(PUBLIC_PRODUCT_COPY.passkeyAccess).toContain("不能用來建立帳號或繞過邀請");
    expect(PUBLIC_PRODUCT_COPY.recovery).toContain("尚未提供自助帳號復原流程");
  });
});
