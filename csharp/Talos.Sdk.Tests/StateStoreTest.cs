using System;
using System.IO;
using System.Text;
using Talos.Sdk;
using Xunit;

namespace Talos.Sdk.Tests
{
    /// <summary>
    /// The machine binding on disk. Runs with no server: these are the
    /// properties the client's constructor depends on before it can talk to
    /// anything.
    /// </summary>
    public class StateStoreTest
    {
        private static StoredBinding Sample() => new StoredBinding
        {
            LicenseKeyHash = StateStore.HashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"),
            ActivationSecret = "s3cr3t-from-the-server",
            MachineId = "01234567-89ab-cdef-0123-456789abcdef",
            Fingerprint = "fp2:deadbeef",
        };

        private static string TmpFile() =>
            Path.Combine(
                Directory.CreateDirectory(
                    Path.Combine(Path.GetTempPath(), "talos-state-" + Guid.NewGuid().ToString("N"))).FullName,
                "state.bin");

        [Fact]
        public void RoundTripsABinding()
        {
            string p = TmpFile();
            var store = new StateStore(p, "tpt_one", "km");
            Assert.Null(store.Load());
            Assert.True(store.Save(Sample()));

            StoredBinding? got = store.Load();
            Assert.NotNull(got);
            Assert.Equal(Sample().LicenseKeyHash, got!.LicenseKeyHash);
            Assert.Equal(Sample().ActivationSecret, got.ActivationSecret);
            Assert.Equal(Sample().MachineId, got.MachineId);
            Assert.Equal(Sample().Fingerprint, got.Fingerprint);

            store.Clear();
            Assert.Null(store.Load());
        }

        [Fact]
        public void UpgradesAFileThatStillCarriesTheKey()
        {
            // The installed base. An older SDK wrote `licenseKey`; a file from
            // it must keep its seat rather than be discarded — charging every
            // existing customer a re-activation for a change made on their
            // behalf would be a poor trade — and the plaintext leaves the disk
            // at the next save.
            string hash = StateStore.HashLicenseKey("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE");
            Assert.Equal(hash, StateStore.ResolveKeyHash(null, "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
            Assert.Equal(hash, StateStore.ResolveKeyHash("", "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
            // A current file wins over a legacy field, so a half-upgraded file
            // does not re-derive from a key that may since have changed.
            Assert.Equal("kept", StateStore.ResolveKeyHash("kept", "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
            Assert.Equal("", StateStore.ResolveKeyHash(null, null));
        }

        [Fact]
        public void SavingNeverWritesTheKeyBack()
        {
            // Whatever a file arrived carrying, what leaves is the hash.
            string p = TmpFile();
            var store = new StateStore(p, "tpt_one", "km");
            store.Save(Sample());
            string raw = Encoding.Latin1.GetString(File.ReadAllBytes(p));
            Assert.DoesNotContain("licenseKey\"", raw);
        }

        [Fact]
        public void DoesNotWriteTheLicenceKeyInTheClear()
        {
            string p = TmpFile();
            new StateStore(p, "tpt_one", "km").Save(Sample());
            string raw = Encoding.Latin1.GetString(File.ReadAllBytes(p));
            // Two claims, and the second is the newer and stronger one. The
            // file is encrypted, so nothing appears in it as typed — but the
            // key is no longer in it at all, in any form: after activation the
            // server resolves the licence from the activation secret, so what
            // used to be a plaintext credential on every customer's disk is now
            // a hash with one local use.
            Assert.DoesNotContain("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", raw);
            Assert.DoesNotContain(Sample().ActivationSecret, raw);
        }

        [Fact]
        public void RefusesAFileFromAnotherProductOrMachine()
        {
            // The product token is authenticated as GCM associated data, and the
            // key is derived from a machine-stable identifier, so a state file
            // cannot be adopted by a different product or a different computer.
            string p = TmpFile();
            new StateStore(p, "tpt_one", "machine-a").Save(Sample());
            Assert.Null(new StateStore(p, "tpt_two", "machine-a").Load());
            Assert.Null(new StateStore(p, "tpt_one", "machine-b").Load());
        }

        [Fact]
        public void TreatsACorruptFileAsNoActivationRatherThanAnError()
        {
            // A damaged cache must cost a re-activation, not a launch failure:
            // this runs in the constructor, before the app has shown anything.
            string p = TmpFile();
            var store = new StateStore(p, "tpt_one", "km");
            store.Save(Sample());
            byte[] good = File.ReadAllBytes(p);

            File.WriteAllBytes(p, new byte[] { good[0], good[1], good[2], good[3] }); // truncated
            Assert.Null(store.Load());

            byte[] badMagic = (byte[])good.Clone();
            badMagic[0] ^= 0xff;
            File.WriteAllBytes(p, badMagic);
            Assert.Null(store.Load());

            byte[] tampered = (byte[])good.Clone();
            tampered[tampered.Length - 1] ^= 0xff; // GCM tag must reject this
            File.WriteAllBytes(p, tampered);
            Assert.Null(store.Load());

            File.WriteAllBytes(p, Array.Empty<byte>());
            Assert.Null(store.Load());
        }

        /// <summary>
        /// Where the file goes on each platform, asserted from any of them.
        /// <para>
        /// This was one call to <c>SpecialFolder.LocalApplicationData</c> with a
        /// comment claiming it meant <c>~/Library/Application Support</c> on
        /// macOS. .NET returns <c>~/.local/share</c> there, so on a Mac the
        /// licence went somewhere no application keeps user data — and the Node
        /// SDK, which does branch per platform, put the same product's binding
        /// somewhere else entirely on macOS and on Linux. Nothing failed; the
        /// two SDKs simply did not share a machine binding, and neither test
        /// looked at a path.
        /// </para>
        /// </summary>
        [Fact]
        public void PutsTheFileWhereEachPlatformKeepsUserData()
        {
            // The slot is a hash prefix of the token; read it back rather than
            // restate it, since what is being asserted is the layout around it.
            string slot = Path.GetFileName(Path.GetDirectoryName(
                StateStore.DefaultPathFor("tpt_one", "linux", "/home/u", null, null))!);

            Assert.Equal(
                Path.Combine(@"C:\Users\u\AppData\Local", "Talos", slot, "state.bin"),
                StateStore.DefaultPathFor("tpt_one", "windows", @"C:\Users\u", @"C:\Users\u\AppData\Local", null));
            Assert.Equal(
                Path.Combine("/Users/u", "Library", "Application Support", "Talos", slot, "state.bin"),
                StateStore.DefaultPathFor("tpt_one", "macos", "/Users/u", null, null));
            Assert.Equal(
                Path.Combine("/home/u", ".local", "share", "talos", slot, "state.bin"),
                StateStore.DefaultPathFor("tpt_one", "linux", "/home/u", null, null));

            // The environment wins where the platform defines one.
            Assert.Equal(
                Path.Combine("/data", "talos", slot, "state.bin"),
                StateStore.DefaultPathFor("tpt_one", "linux", "/home/u", null, "/data"));
            Assert.Equal(
                Path.Combine(@"D:\local", "Talos", slot, "state.bin"),
                StateStore.DefaultPathFor("tpt_one", "windows", @"C:\Users\u", @"D:\local", null));

            // And a host with no home at all still gets a writable path.
            Assert.StartsWith(
                Path.GetTempPath(),
                StateStore.DefaultPathFor("tpt_one", "linux", "", null, null));
        }

        [Fact]
        public void GivesEachProductItsOwnSlot()
        {
            string a = StateStore.DefaultPath("tpt_one");
            string b = StateStore.DefaultPath("tpt_two");
            Assert.NotEqual(a, b);
            Assert.EndsWith("state.bin", a);
            // The token itself must not appear in the path — the directory is
            // named by a hash of it, so nothing is assumed about its alphabet.
            Assert.DoesNotContain("tpt_one", a);
        }
    }
}
