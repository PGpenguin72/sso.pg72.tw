-- Stores the original Google profile image URL while the user has switched
-- their public avatar (user.image, which feeds the OIDC `picture` claim) to
-- the self-hosted generated identicon, so the choice stays reversible.
alter table "user" add column "googleImage" text;
