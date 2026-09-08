using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The frozen wire vectors, verified by this SDK.
    /// <para>
    /// Every other verification test here mints a token with a key it generated
    /// moments earlier and then verifies it — the SDK agreeing with itself. This
    /// one reads <c>sdks/contract-vectors.json</c>: fixed keys, tokens signed by
    /// the Rust server code and committed to the repository. If the format drifts
    /// on either side, one of the three implementations that read this file stops
    /// agreeing with bytes that predate all of them, which is the alarm a
    /// self-consistent test cannot raise.
    /// </para>
    /// <para>
    /// Deployed applications pin a key and verify these shapes for years. That is
    /// why the wire format is additive-only, and this is where the rule is
    /// enforced rather than merely written down.
    /// </para>
    /// </summary>
    public class WireVectorsTest
    {
        private static readonly JsonElement Doc = Load();
        private static readonly string Aud = Doc.GetProperty("aud").GetString()!;
        private static readonly string Nonce = Doc.GetProperty("nonce").GetString()!;

        private static JsonElement Load()
        {
            // Copied beside the test assembly by the .csproj; the file itself
            // lives at the repository's `sdks/` root because it belongs to no
            // single language.
            string path = Path.Combine(AppContext.BaseDirectory, "contract-vectors.json");
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            return doc.RootElement.Clone();
        }

        private static byte[] Key(string name) =>
            Convert.FromBase64String(Doc.GetProperty("keys").GetProperty(name).GetString()!);

        /// <summary>
        /// Verify one vector with one key, through the same entry point the client
        /// uses for that token class — a manifest and a keyset take different
        /// paths, and a vector suite that verified everything through one of them
        /// would prove less than it looks.
        /// </summary>
        private static JsonElement VerifyWith(JsonElement vector, byte[] key)
        {
            string typ = vector.GetProperty("typ").GetString()!;
            string token = vector.GetProperty("token").GetString()!;
            return typ switch
            {
                "keyset" => TalosCompact.VerifyKeyset(key, Aud, token),
                "manifest" => TalosCompact.VerifyManifest(key, Aud, token),
                _ => TalosCompact.Verify(key, typ, Aud, Nonce, token),
            };
        }

        private static IEnumerable<JsonElement> Vectors(string group)
        {
            foreach (JsonElement v in Doc.GetProperty(group).EnumerateArray())
                yield return v;
        }

        private static JsonElement Named(string name)
        {
            foreach (JsonElement v in Vectors("vectors"))
                if (v.GetProperty("name").GetString() == name)
                    return v;
            throw new InvalidOperationException($"no vector named {name}");
        }

        [Fact]
        public void EveryCommittedVectorVerifiesUnderTheKeyItNames()
        {
            int seen = 0;
            foreach (JsonElement v in Vectors("vectors"))
            {
                string name = v.GetProperty("name").GetString()!;
                JsonElement claims = VerifyWith(v, Key(v.GetProperty("key").GetString()!));
                Assert.Equal(v.GetProperty("typ").GetString(), claims.GetProperty("typ").GetString());
                Assert.Equal(Aud, claims.GetProperty("aud").GetString());
                seen++;
                _ = name;
            }
            // A file that failed to load, or a rename that emptied the list, must
            // not read as seven passing vectors.
            Assert.Equal(7, seen);
        }

        [Fact]
        public void AVectorDoesNotVerifyUnderAKeyItDoesNotName()
        {
            foreach (JsonElement v in Vectors("vectors"))
            {
                string named = v.GetProperty("key").GetString()!;
                foreach (string other in new[] { "license", "anchor", "release" })
                {
                    if (other == named) continue;
                    Assert.ThrowsAny<TalosException>(() => VerifyWith(v, Key(other)));
                }
            }
        }

        [Fact]
        public void EveryNegativeVectorIsRefused()
        {
            int seen = 0;
            foreach (JsonElement v in Vectors("negative"))
            {
                Assert.Throws<TalosSignatureException>(() => VerifyWith(v, Key(v.GetProperty("key").GetString()!)));
                seen++;
            }
            Assert.Equal(5, seen);
        }

        /// <summary>
        /// The claims an application actually reads, spelled out. The signature
        /// checks above would still pass if a claim were renamed on both sides at
        /// once; these are the names a deployed build looks for.
        /// </summary>
        [Fact]
        public void TheClaimsAnApplicationReadsAreWhereTheyHaveAlwaysBeen()
        {
            JsonElement act = VerifyWith(Named("activation"), Key("license"));
            JsonElement lic = act.GetProperty("lic");
            Assert.True(lic.GetProperty("features").GetProperty("pro").GetBoolean());
            Assert.Equal(5, lic.GetProperty("features").GetProperty("seats").GetInt32());
            Assert.Equal(72, lic.GetProperty("grace_h").GetInt32());
            Assert.Equal(24, lic.GetProperty("reval_h").GetInt32());
            Assert.Equal(JsonValueKind.Null, lic.GetProperty("lic_exp").ValueKind);

            JsonElement val = VerifyWith(Named("validation"), Key("license"));
            Assert.Equal("valid", val.GetProperty("decision").GetString());
            Assert.True(val.GetProperty("grace_until").GetInt64() > val.GetProperty("server_time").GetInt64());

            JsonElement beat = VerifyWith(Named("heartbeat"), Key("license"));
            Assert.Equal(3600, beat.GetProperty("heartbeat_interval_s").GetInt32());
            Assert.True(beat.GetProperty("upd").GetBoolean());

            JsonElement lease = VerifyWith(Named("lease"), Key("license"));
            Assert.Equal(3, lease.GetProperty("max_seats").GetInt32());
            Assert.Equal(1, lease.GetProperty("seats_in_use").GetInt32());
            Assert.Equal("inst-1", lease.GetProperty("inst").GetString());

            // The keyset is how an application that pinned only the anchor learns
            // the licence key. If this shape moves, a rotation stops reaching the
            // field and every install fails at once.
            JsonElement keyset = VerifyWith(Named("keyset"), Key("anchor"));
            string licenseKeyB64 = Doc.GetProperty("keys").GetProperty("license").GetString()!;
            bool found = false;
            foreach (JsonElement k in keyset.GetProperty("keys").EnumerateArray())
            {
                if (k.GetProperty("purpose").GetString() == "license"
                    && k.GetProperty("status").GetString() == "active"
                    && k.GetProperty("pk").GetString() == licenseKeyB64)
                {
                    found = true;
                }
            }
            Assert.True(found, "the keyset must carry the product's active licence key");

            JsonElement man = VerifyWith(Named("manifest"), Key("release"));
            Assert.Equal("1.2.0", man.GetProperty("version").GetString());
            Assert.Equal(7, man.GetProperty("release_seq").GetInt32());
            JsonElement art = man.GetProperty("artifacts")[0];
            Assert.Equal("notes-1.2.0-x64.exe", art.GetProperty("filename").GetString());
            Assert.Equal(64, art.GetProperty("sha256").GetString()!.Length);
        }
    }
}
