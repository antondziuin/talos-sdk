using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static Talos.Sdk.WalletProtocol;

namespace Talos.Sdk
{
    public sealed partial class RegistryLicenseClient
    {
        private sealed class ChainHead
        {
            internal long Number, Timestamp;
            internal string Hash = "";
            internal string Tag => "0x" + Number.ToString("x", CultureInfo.InvariantCulture);
        }
        private sealed class LicenseObservation { internal long Revision; internal bool Revoked; }
        private sealed class ChainObservations
        {
            internal ChainHead Head = new ChainHead();
            internal readonly Dictionary<string, LicenseObservation> Licenses = new Dictionary<string, LicenseObservation>(StringComparer.Ordinal);
        }
        private static bool SameHead(ChainHead a, ChainHead b) => a.Number == b.Number && a.Timestamp == b.Timestamp && DeviceProtocol.Eq(a.Hash, b.Hash);
        private static ChainHead Block(JsonElement value)
        {
            try
            {
                string hash = Str(value, "hash"); Bytes(hash, 32);
                return new ChainHead { Number = Quantity(Str(value, "number")), Timestamp = Quantity(Str(value, "timestamp")), Hash = hash.ToLowerInvariant() };
            }
            catch (Exception e) when (e is ArgumentException || e is FormatException || e is InvalidOperationException || e is KeyNotFoundException)
            { throw new RegistryLicenseException("invalid_registry_rpc_response"); }
        }
        private static ChainObservations? ChainState(string? raw)
        {
            if (raw == null) return null;
            try
            {
                if (raw.Length > 32768) throw new ArgumentException();
                using var doc = JsonDocument.Parse(raw); var root = doc.RootElement; var head = root.GetProperty("head");
                string encoded = Str(head, "number"), hash = Str(head, "hash");
                if (root.GetProperty("v").GetInt32() != 1 || !long.TryParse(encoded, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
                    || number < 0 || number > 9007199254740991 || encoded != number.ToString(CultureInfo.InvariantCulture)) throw new ArgumentException();
                Bytes(hash, 32); long timestamp = head.GetProperty("timestamp").GetInt64();
                if (timestamp < 0 || timestamp > 9007199254740991) throw new ArgumentException();
                var state = new ChainObservations { Head = new ChainHead { Number = number, Hash = hash.ToLowerInvariant(), Timestamp = timestamp } };
                var licenses = root.GetProperty("licenses");
                if (licenses.ValueKind != JsonValueKind.Object || licenses.EnumerateObject().Count() > 64) throw new ArgumentException();
                foreach (var item in licenses.EnumerateObject())
                {
                    Bytes(item.Name, 32); if (item.Name != item.Name.ToLowerInvariant()) throw new ArgumentException();
                    long revision = item.Value.GetProperty("revision").GetInt64(); bool revoked = item.Value.GetProperty("revoked").GetBoolean();
                    if (revision < 0 || revision > 9007199254740991) throw new ArgumentException();
                    state.Licenses.Add(item.Name, new LicenseObservation { Revision = revision, Revoked = revoked });
                }
                return state;
            }
            catch (Exception e) when (e is JsonException || e is ArgumentException || e is FormatException || e is InvalidOperationException || e is KeyNotFoundException || e is OverflowException)
            { throw new RegistryLicenseException("invalid_registry_chain_state"); }
        }
        private static string EncodeChainState(ChainObservations state) => Write(w =>
        {
            w.WriteStartObject(); w.WriteNumber("v", 1); w.WritePropertyName("head"); w.WriteStartObject();
            w.WriteString("number", state.Head.Number.ToString(CultureInfo.InvariantCulture)); w.WriteString("hash", state.Head.Hash); w.WriteNumber("timestamp", state.Head.Timestamp); w.WriteEndObject();
            w.WritePropertyName("licenses"); w.WriteStartObject();
            foreach (var item in state.Licenses.OrderBy(p => p.Key, StringComparer.Ordinal))
            { w.WritePropertyName(item.Key); w.WriteStartObject(); w.WriteNumber("revision", item.Value.Revision); w.WriteBoolean("revoked", item.Value.Revoked); w.WriteEndObject(); }
            w.WriteEndObject(); w.WriteEndObject();
        });
        private Task<JsonElement> BlockAt(string endpoint, string tag, CancellationToken ct) => Rpc(endpoint, "eth_getBlockByNumber", w => { w.WriteStartArray(); w.WriteStringValue(tag); w.WriteBooleanValue(false); w.WriteEndArray(); }, ct);

        private bool Observe(ChainHead block, ChainObservations? initial, string licenseId, long revision, bool revoked, bool refused, bool reorg, int generation)
        {
            lock (_gate)
            {
                RequireOpen(); if (generation != _generation) throw new RegistryLicenseException("license_changed_during_validation");
                using var mutex = StorageMutex(); WaitMutex(mutex);
                try
                {
                    var saved = _store.Load();
                    if (saved?.MachineKey == null || saved.MachinePublicKey == null || Hex(Convert.FromBase64String(saved.MachinePublicKey)) != DeviceKey) throw new RegistryLicenseException("device_key_missing");
                    var seen = ChainState(saved.RegistryChainState);
                    if (seen != null && block.Number < seen.Head.Number) throw new TransientRpcException("rpc_block_lag");
                    if (seen != null && !SameHead(seen.Head, block) && (initial == null || !SameHead(seen.Head, initial.Head))) throw new TransientRpcException("rpc_head_changed");
                    string id = licenseId.ToLowerInvariant();
                    LicenseObservation? prior = null; seen?.Licenses.TryGetValue(id, out prior);
                    if (!refused && prior != null && revision < prior.Revision)
                    {
                        if (reorg) throw new RegistryLicenseException("registry_reorg_conflict");
                        throw new TransientRpcException("rpc_state_rollback");
                    }
                    var state = seen ?? new ChainObservations();
                    if (!state.Licenses.ContainsKey(id) && state.Licenses.Count >= 64) throw new RegistryLicenseException("registry_observation_limit");
                    bool terminal = revoked || prior?.Revoked == true;
                    state.Licenses[id] = new LicenseObservation { Revision = Math.Max(revision, prior?.Revision ?? 0), Revoked = terminal }; state.Head = block;
                    saved.RegistryChainState = EncodeChainState(state);
                    saved.TimeHighWater = Math.Max(saved.TimeHighWater, block.Timestamp); saved.OfflineSeen = Math.Max(saved.OfflineSeen, Now());
                    if (!_store.Save(saved)) throw new RegistryLicenseException("device_state_not_saved");
                    return terminal;
                }
                finally { mutex.ReleaseMutex(); }
            }
        }
    }
}
