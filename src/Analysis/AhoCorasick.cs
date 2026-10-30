namespace AgentScan.Analysis;

internal sealed class AhoCorasick
{
    private sealed class Node
    {
        public readonly Dictionary<byte, int> Next = new();
        public int Fail;
        public List<int>? Out;
    }

    private readonly List<Node> _nodes = new();
    private readonly List<byte[]> _patterns = new();
    private int[]? _goto;
    private List<int>?[] _out = Array.Empty<List<int>?>();
    private bool _built;

    public IReadOnlyList<byte[]> Patterns => _patterns;

    public AhoCorasick() => _nodes.Add(new Node());

    public int Add(byte[] pattern)
    {
        if (_built) throw new InvalidOperationException("автомат уже построен");
        if (pattern.Length == 0) return -1;
        int id = _patterns.Count;
        _patterns.Add(pattern);

        int cur = 0;
        foreach (byte b in pattern)
        {
            if (!_nodes[cur].Next.TryGetValue(b, out int nxt))
            {
                nxt = _nodes.Count;
                _nodes.Add(new Node());
                _nodes[cur].Next[b] = nxt;
            }
            cur = nxt;
        }
        (_nodes[cur].Out ??= new List<int>()).Add(id);
        return id;
    }

    public void Build()
    {
        if (_built) return;
        int n = _nodes.Count;
        var q = new Queue<int>();
        _goto = new int[n * 256];

        for (int c = 0; c < 256; c++)
        {
            if (_nodes[0].Next.TryGetValue((byte)c, out int nx))
            {
                _nodes[nx].Fail = 0;
                _goto[c] = nx;
                q.Enqueue(nx);
            }
        }

        while (q.Count > 0)
        {
            int u = q.Dequeue();
            for (int c = 0; c < 256; c++)
            {
                if (_nodes[u].Next.TryGetValue((byte)c, out int v))
                {
                    _nodes[v].Fail = _goto[_nodes[u].Fail * 256 + c];
                    var fo = _nodes[_nodes[v].Fail].Out;
                    if (fo is not null)
                    {
                        _nodes[v].Out ??= new List<int>();
                        foreach (int id in fo)
                            if (!_nodes[v].Out!.Contains(id)) _nodes[v].Out!.Add(id);
                    }
                    _goto[u * 256 + c] = v;
                    q.Enqueue(v);
                }
                else _goto[u * 256 + c] = _goto[_nodes[u].Fail * 256 + c];
            }
        }

        _out = new List<int>?[n];
        for (int i = 0; i < n; i++) _out[i] = _nodes[i].Out;
        _built = true;
    }

    public int State { get; set; }

    public void Scan(ReadOnlySpan<byte> data, Action<int, int> onMatch, bool keepState = false)
    {
        if (!_built) Build();
        int[] g = _goto!;
        var outs = _out;
        int s = keepState ? State : 0;
        for (int i = 0; i < data.Length; i++)
        {
            s = g[(s << 8) | data[i]];
            var o = outs[s];
            if (o is null) continue;
            for (int k = 0; k < o.Count; k++)
            {
                int id = o[k];
                onMatch(id, i - _patterns[id].Length + 1);
            }
        }
        State = s;
    }
}
