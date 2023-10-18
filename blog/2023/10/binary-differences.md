- 2023-10-13
- A Comparison of Tools for Binary Diffing

Binary diffing is a useful method for debugging issues in new builds,
reverse engineering exploits from security patches, and updating tools to
work with modified binary layouts. This article will compare:

- [Diaphora](http://diaphora.re/)
- [BinDiff](https://www.zynamics.com/bindiff.html)

For our test we will compare two DLLs while considering:

```
-rw-r--r-- 1 user user  28M Oct 18 18:22 big-A.dll
-rw-r--r-- 1 user user  18M Oct 18 18:22 big-B.dll
-rw-r--r-- 1 user user 7.2M Oct 18 16:27 small-A.dll
-rw-r--r-- 1 user user 7.2M Oct 18 16:27 small-B.dll
```

1. Ease of installation
2. Ease of use (includes overhead)
3. Accuracy of detecting differences
4. Extensibility

# Intro to Diffing

Textual diffing is a common practice when reviewing [patches](https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e) in source-code.

```diff
        l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC,
                           sizeof(rfc), (unsigned long) &rfc, endptr - ptr);

-       if (test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
+       if (remote_efs &&
            test_bit(FLAG_EFS_ENABLE, &chan->flags)) {
            chan->remote_id = efs.id;
            chan->remote_stype = efs.stype;
            chan->remote_msdu = le16_to_cpu(efs.msdu);
```

or when you are adding code to a Git repository. How does this work though?
Textual diffing revolves around finding the [longest common subsequence](https://en.wikipedia.org/wiki/Longest_common_subsequence)
between two texts.

```
A B C D E F
A   C D E  G
```

We can detect "edits" by identifying which strings have to be inserted or
deleted to arrive at the new string. If we want to improve the output for
code then we can operate on [lexemes](https://en.wikipedia.org/wiki/Lexical_analysis) or entire lines instead of individual
characters. Naturally, this increases complexity because the algorithm needs
the ability to parse the input text as the target language.

# Intro to Binary Diffing

Binary diffing is more complicated because we have to determine what a
"difference" means.

- Do we consider semantically equivalent code to be the same?
- Do we want to consider changes to miscellaneous sections (e.g. `.comment`)
- Do we want to consider changes to the environment? (e.g. updated static libc)
- Do we want to consider the entire file as raw bytes?
- Do we want to find **similar** functions between unrelated files?

Depending on your use-case, some of these perspectives might have no value or
be invaluable.

To help illustrate this, consider the snippet below.

```rs
fn main() {
    let image = include_bytes!("cat.jpg");
}
```

Do we care _if_ the image is changed or care _how_ the image is changed?

If we want semantically aware diffs then we need dedicated parsers for each
file format (e.g. ELF, PE32). Furthermore, we might need additional parsers for
any data inside the files (e.g. x64, ARMv8, Unicode, ASN.1, WAV, etc.).

> **Assembly**
>
> ```diff
> mov eax, 1337
> - sub eax, 1337
> + add eax, 1337
> ```
>
> **Bytes**
>
> ```diff
> b8 39 05 00 00
> - 2d 39
> + 05 39
> 05 00 00
> ```
>
> **Pseudo-Code**
> ```diff
> - RegWrite(eax, 0)
> + RegWrite(eax, 2674)
> ```

Parsers capable of answering format specific questions introduce a _lot_ of
complexity and overhead so it is important to know the capabilities of your
chosen diffing tool.

# Diaphora

[Diaphora](http://diaphora.re/) is an open-source diffing tool boasting an
impressive feature-set. The features I'm interested in are as follows:

- Diffing assembler
- Diffing control flow graphs
- Support for manual matches
- Diffing pseudo-code
- Importing IDB of an original image for a similar image.

If you are interested in the Diaphora heuristics, they are described in the
[`docs/`](https://github.com/joxeankoret/diaphora/tree/master/doc) folder of
the GitHub repository.

### Ease of installation

Diaphora is very straightforward to install.

```sh
$ git clone https://github.com/joxeankoret/diaphora.git
```
Then you can point IDA Pro to the `diaphora.py` script in the Command File
prompt.

### Ease of use

Diaphora serializes diffing information into a Sqlite database. Initially, we
export a Sqlite image for the first target using IDA Pro. Then we load the
second target into IDA. This time, we can select to diff the second target
against the Sqlite database of the first target.

If you're interested, the database schema is available [here](https://github.com/joxeankoret/diaphora/blob/master/db_support/schema.py).

```sql
create table if not exists functions (
                          id integer primary key,
                          name varchar(255),
                          address text unique,
                          nodes integer,
                          edges integer,
                          indegree integer,
                          outdegree integer,
                          size integer,
                          instructions integer,
                          mnemonics text,
                          names text,
                          prototype text,
                          cyclomatic_complexity integer,
                          ...
```

You can configure some of the heuristics and information used by and stored in
the database. This allows you to reduce the analysis time and database size
for large targets. In my case, I disabled slow heuristics then disabled
exporting instructions.

![Diaphora Options](assets/diaphora_options.webp)

Attempting to export the database took a long time... a _long_ time. The
time to export `big-A.dll` and `big-B.dll` took over 50 minutes, **each**.
The final file of the sqlite databases were ~130MB each.

### Accuracy of detecting differences

Once the databases were made, Diaphora attempted to diff them. However, the
diffing process took over an hour then crashed before results were produced.
I think Diaphora consumes a huge amount of memory which causes it to be OOM
killed. Perhaps Diaphora would benefit from streaming or being written in a
more efficient language (e.g. C or a language with C-extension interop).

To actually produce results, I have used Diaphora on `small-A.dll` and
`small-B.dll`. It took over 20 minutes, each, to export both images but only
21 seconds to diff. It should be noted that Diaphora crashed during the export
process but recovered itself. The exports are absolutely huge.

```
-rw-r--r-- 1 user user 441M Oct 18 16:49 small-A.dll.sqlite
-rw-r--r-- 1 user user 439M Oct 18 16:48 small-B.dll.sqlite
```

![Diaphora Match](assets/diaphora_match.webp)

The UI for inspecting differences is very pleasant for Diaphora. It is easy to
compare differences between images. In addition, the matches seem to be very
reliable which is nice. You can easily see which instructions have been
changed between the two snippets. This patch mode also exists for the IDA
pseudo-code view (these .NET DLLs don't have pseudocode).

### Extensibility

Diaphora is written in pure Python so it can be easily modified to add or
remove heuristics. You can add a new heuristic [here](https://github.com/joxeankoret/diaphora/blob/master/diaphora_heuristics.py).

```py
HEURISTICS.append({
    "name": "Coin Toss",
    "category": "Partial",
    "ratio": HEUR_TYPE_RATIO,
    "sql": """
        SELECT abs(random()) / 9223372036854775807.0
        %POSTFIX%
    """,
    "flags": [HEUR_FLAG_SAME_CPU]
})
```

However, the heuristic is easy to add if it can utilise the sqlite3 export. It
is possible to add new fields to the database but will require some awkward
restructing of code.

# BinDiff

[BinDiff](https://www.zynamics.com/bindiff.html) is a renowned diffing tool
with the following capabilities:

- Diffing assembler
- Diffing control flow graphs
- Importing IDB of an original image for a similar image.

If you are interested in the BinDiff heuristics, they are described
[here](https://www.zynamics.com/bindiff/manual/index.html#chapUnderstanding).

### Ease of installation

Installation is also straightforward. You can follow the instructions
[here](https://www.zynamics.com/bindiff/manual/index.html#N201AE) to download
a binary from the releases page then point BinDiff to the IDA installation.

### Ease of use

Once BinDiff is configured, you can hit `Ctrl+6` in IDA to export information
about the currently loaded file as a `.binExport`. After both files have been
exported, you can diff the exports.

The `.binExport` is another sqlite3 database with the following
[schema](https://github.com/google/bindiff/blob/0b5bb854907ce83af5f67200dbd3b7fd36cb9a86/database_writer.cc#L204).
An excerpt is included below.

```cpp
  NA_RETURN_IF_ERROR(database_.Execute(
      "CREATE TABLE basicblock ("
      "id INT,"
      "functionid INT,"
      "address1 BIGINT,"
      "address2 BIGINT,"
      "algorithm SMALLINT,"
      "evaluate BOOLEAN,"
      "PRIMARY KEY(id),"
      "FOREIGN KEY(functionid) REFERENCES function(id),"
      "FOREIGN KEY(algorithm) REFERENCES basicblockalgorithm(id)"
      ")"));
```

I was able to export both `big-A.dll` and `big-B.dll` in ~30 minutes then diff
them after 22 minutes.

![BinDiff Options](assets/bindiff_options.webp)

In order to compare with Diaphora, I diffed both `small-A.dll` and
`small-B.dll`. The diff took less than 5 minutes (including export).

```
-rw-r--r-- 1 jack jack 30M Oct 18 17:13 small-A.dll.BinExport
-rw-r--r-- 1 jack jack 24M Oct 18 17:13 small-A.dll_vs_small-B.dll.BinDiff
-rw-r--r-- 1 jack jack 30M Oct 18 17:13 small-B.dll.BinExport
```

The file sizes of the exports are pretty reasonable compared to the original
file size.

### Accuracy of detecting differences

BinDiff was pretty decent at detecting similar functions but manual review was
necessary for a large number of functions which BinDiff was unable to match.

These are functions which BinDiff was able to successfully match.

![BinDiff match](assets/bindiff_a_match.webp)
![BinDiff match](assets/bindiff_b_match.webp)

However, this is an example where BinDiff flounders. The "match" is matched via
call flow. There are undeniable similarities:

Both versions call a function at the same offset (`240i64`) from `a1`.
```c
(*(void (__fastcall **)(QWORD, __int128 *))(**(QWORD **)a1 + 240164))(*(_QWORD *)a1, &v11);
```

![BinDiff bad match](assets/bindiff_a_match2.webp)
![BinDiff bad match](assets/bindiff_b_match2.webp)

But these functions clearly have some differences in what they're computing so
futher analysis is needed to see if another function was inlined in the new
version, replacing the tail-call in the second version. The interface is
pretty clunky compared with Diaphora because the BinDiff GUI can only
display the call graphs of the functions. In order to view the changes
yourself, you will have to copy the primary and secondary address of each
match then inspect those locations in separate IDA instances.

### Extensibility

BinDiff is written in C++ so it is a bit trickier to extend but you can add
new heuristics
[here](https://github.com/google/bindiff/blob/main/match/call_graph.cc#L358)
and [here](https://github.com/google/bindiff/blob/main/match/flow_graph.cc#L200)
without too much difficulty.

```cpp
MatchingStepsFlowGraph GetDefaultMatchingStepsBasicBlock() {
    ...
    for (auto* step : std::initializer_list<MatchingStepFlowGraph*>{
            ...
            new MyCustomMatcher(), // new heuristic
            }) {
        (*algorithms)[step->name()] = step;
    }
    ...
}

namespace security::bindiff {
class MyCustomMatcher : public MatchingStepFlowGraph {
public:
    MyCustomMatcher()
        : MatchingStepFlowGraph("coinToss", "Coin Toss") {}

    bool FindFixedPoints(FlowGraph* primary, FlowGraph* secondary,
                         const VertexSet& vset1, const VertexSet& vset2,
                         FixedPoint *fixed_point, MatchingContext *ctx,
                         MatchingStepFlowGraph *matching_steps) override;
private:
    void GetUnmatchedBasicBlocksByLuck(const FlowGraph *flow_graph,
                                       const VertexSet& verts,
                                       VertexIntMap *basic_blocks_map);
}

bool MyCustomMatcher::FindFixedPoints(
        FlowGraph* primary, FlowGraph* secondary,
        const VertexSet& vset1, const VertexSet& vset2,
        FixedPoint *fixed_point, MatchingContext *ctx,
        MatchingStepFlowGraph *matching_steps) {
    VertexIntMap vmap1;
    VertexIntMap vmap2;
    GetUnmatchedBasicBlocksByLuck(primary,   vset1, &vmap1);
    GetUnmatchedBasicBlocksByLuck(secondary, vset2, &vmap2);
    return FindFixedPointsBasicBlockInternal(primary, secondary, &vmap1, &vmap2,
                                             fixed_point, ctx, matching_steps);
}

void MyCustomMatcher::GetUnmatchedBasicBlocksByLuck(
        const FlowGraph *flow_graph, const VertexSet &verts,
        VertexIntMap *basic_blocks_map) {
    basic_blocks_map->clear();
    for (auto vertex : vertices)
        if (!flow_graph->GetFixedPoint(vertex))
            // randomly map our vertex to an int, maybe we're right :)
            basic_blocks_map->emplace(rand(), vertex);
}
} // namespace security::bindiff
```

Clearly, this is a decent amount of code compared to Diaphora but that is what
you get with C++. Similarly with Diaphora, a decent amount of effort will be
needed to add new database fields.

# Summary

The Diaphora user experience is much nicer than BinDiff. However, Diaphora is
unable to work with "large" binaries so it is pretty limited in its utility.
If you are able to use Diaphora then I would recommend it but otherwise rely on
BinDiff.
