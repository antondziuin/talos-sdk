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
            LicenseKey = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE",
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
            Assert.Equal(Sample().LicenseKey, got!.LicenseKey);
            Assert.Equal(Sample().ActivationSecret, got.ActivationSecret);
            Assert.Equal(Sample().MachineId, got.MachineId);
            Assert.Equal(Sample().Fingerprint, got.Fingerprint);

            store.Clear();
            Assert.Null(store.Load());
        }

        [Fact]
        public void DoesNotWriteTheLicenceKeyInTheClear()
        {
            string p = TmpFile();
            new StateStore(p, "tpt_one", "km").Save(Sample());
            string raw = Encoding.Latin1.GetString(File.ReadAllBytes(p));
            Assert.DoesNotContain(Sample().LicenseKey, raw);
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
