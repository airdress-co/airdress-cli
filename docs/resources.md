# Resources

What runs behind your airdress is declared in manifests and applied, the
way Kubernetes applies a file: your airdress computes the change and
reports what it did. Manifests are YAML (JSON is accepted); several
documents in one file are separated by `---`.

```yaml
apiVersion: airdress.co/v1alpha1
kind: InferencePoolMember
metadata:
  name: my-nas
spec:
  # …
```

```sh
airdress apply -f pool.yaml                  # server-side apply
airdress apply -f pool.yaml --dry-run        # predict, write nothing
airdress diff  -f pool.yaml                  # the same as --dry-run

airdress get                                 # the Kinds this airdress knows
airdress get InferencePoolMember             # every resource of one Kind
airdress get InferencePoolMember/my-nas      # one, as YAML
airdress get things                          # a lowercase or plural Kind resolves too

airdress describe InferencePoolMember/my-nas # spec, status and conditions
airdress delete   InferencePoolMember/my-nas
airdress delete   -f pool.yaml               # every document in the file
```

All verbs act on the [current airdress](getting-started.md#which-airdress-a-command-acts-on)
and accept `--output json`.

Functions are resources too (`kind: Function`), but
[`airdress fn deploy`](functions.md) is the way to get one running: it
publishes the source, then applies or promotes for you.

## As a machine

An approved machine can apply with its own key instead of your sign-in:

```sh
airdress apply -f pool.yaml --machine-key <file> --operator-url https://<your airdress address>
```

Your airdress decides by the machine's grants. A CI machine usually has
none for `apply` and is answered `403 resource_forbidden`; that is by
design, since the grant to apply is the grant itself.
