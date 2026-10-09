//! A unified diff from a file's old and new text, for adapters whose
//! harness reports an edit as the two texts (ACP's `diff` content) rather
//! than as a patch.
//!
//! A line-level longest-common-subsequence diff with three lines of
//! context. Past [`MAX_CELLS`] it gives up on alignment and shows the whole
//! file replaced, which is still a correct diff, only a less helpful one.

/// The largest `old × new` line table aligned.
pub const MAX_CELLS: usize = 4_000_000;
const CONTEXT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep(usize, usize),
    Del(usize),
    Add(usize),
}

fn ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let (n, m) = (a.len(), b.len());
    if n.saturating_mul(m) > MAX_CELLS {
        let mut v: Vec<Op> = (0..n).map(Op::Del).collect();
        v.extend((0..m).map(Op::Add));
        return v;
    }
    // lcs[i][j] = LCS of a[i..] and b[j..].
    let w = m + 1;
    let mut lcs = vec![0u32; (n + 1) * w];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i * w + j] = if a[i] == b[j] {
                lcs[(i + 1) * w + j + 1] + 1
            } else {
                lcs[(i + 1) * w + j].max(lcs[i * w + j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut v = Vec::with_capacity(n + m);
    while i < n && j < m {
        if a[i] == b[j] {
            v.push(Op::Keep(i, j));
            i += 1;
            j += 1;
        } else if lcs[(i + 1) * w + j] >= lcs[i * w + j + 1] {
            v.push(Op::Del(i));
            i += 1;
        } else {
            v.push(Op::Add(j));
            j += 1;
        }
    }
    v.extend((i..n).map(Op::Del));
    v.extend((j..m).map(Op::Add));
    v
}

/// `--- a/<path>` / `+++ b/<path>` and the hunks turning `old` into `new`.
/// An absent `old` is a new file.
pub fn unified(path: &str, old: Option<&str>, new: &str) -> String {
    let a: Vec<&str> = old.map(|o| o.lines().collect()).unwrap_or_default();
    let b: Vec<&str> = new.lines().collect();
    let ops = ops(&a, &b);
    let mut out = format!(
        "--- {}\n+++ b/{path}\n",
        if old.is_some() {
            format!("a/{path}")
        } else {
            "/dev/null".to_owned()
        }
    );
    // Group changes into hunks with CONTEXT lines around them.
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| !matches!(o, Op::Keep(..)))
        .map(|(k, _)| k)
        .collect();
    let mut k = 0;
    while k < changed.len() {
        let start = changed[k].saturating_sub(CONTEXT);
        let mut end = changed[k];
        while k < changed.len() && changed[k] <= end + 2 * CONTEXT {
            end = changed[k];
            k += 1;
        }
        let end = (end + CONTEXT + 1).min(ops.len());
        let hunk = &ops[start..end];
        let a_start = hunk
            .iter()
            .find_map(|o| match o {
                Op::Keep(i, _) | Op::Del(i) => Some(*i),
                Op::Add(_) => None,
            })
            .unwrap_or_else(|| {
                // Only additions: they go after the a-line kept before them.
                ops[..start]
                    .iter()
                    .rev()
                    .find_map(|o| match o {
                        Op::Keep(i, _) | Op::Del(i) => Some(*i + 1),
                        Op::Add(_) => None,
                    })
                    .unwrap_or(0)
            });
        let b_start = hunk
            .iter()
            .find_map(|o| match o {
                Op::Keep(_, j) | Op::Add(j) => Some(*j),
                Op::Del(_) => None,
            })
            .unwrap_or_else(|| {
                ops[..start]
                    .iter()
                    .rev()
                    .find_map(|o| match o {
                        Op::Keep(_, j) | Op::Add(j) => Some(*j + 1),
                        Op::Del(_) => None,
                    })
                    .unwrap_or(0)
            });
        let a_len = hunk.iter().filter(|o| !matches!(o, Op::Add(_))).count();
        let b_len = hunk.iter().filter(|o| !matches!(o, Op::Del(_))).count();
        // A zero-length range names the line before it (diff's convention).
        let a_at = if a_len == 0 { a_start } else { a_start + 1 };
        let b_at = if b_len == 0 { b_start } else { b_start + 1 };
        out.push_str(&format!("@@ -{a_at},{a_len} +{b_at},{b_len} @@\n"));
        for o in hunk {
            match o {
                Op::Keep(i, _) => {
                    out.push(' ');
                    out.push_str(a[*i]);
                }
                Op::Del(i) => {
                    out.push('-');
                    out.push_str(a[*i]);
                }
                Op::Add(j) => {
                    out.push('+');
                    out.push_str(b[*j]);
                }
            }
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_changed_line_with_context() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\n";
        let new = "a\nb\nc\nd\nE\nf\ng\nh\n";
        assert_eq!(
            unified("x.txt", Some(old), new),
            "--- a/x.txt\n+++ b/x.txt\n@@ -2,7 +2,7 @@\n b\n c\n d\n-e\n+E\n f\n g\n h\n"
        );
    }

    #[test]
    fn a_new_file_is_all_additions() {
        assert_eq!(
            unified("n.rs", None, "fn main() {}\n"),
            "--- /dev/null\n+++ b/n.rs\n@@ -0,0 +1,1 @@\n+fn main() {}\n"
        );
    }

    #[test]
    fn far_apart_changes_are_two_hunks() {
        let old: String = (0..30).map(|i| format!("l{i}\n")).collect();
        let new = old.replace("l2\n", "L2\n").replace("l25\n", "L25\n");
        let d = unified("f", Some(&old), &new);
        assert_eq!(d.matches("@@ ").count(), 2, "{d}");
        assert!(d.contains("-l2\n+L2\n") && d.contains("-l25\n+L25\n"));
    }

    #[test]
    fn identical_texts_have_no_hunk() {
        assert_eq!(unified("f", Some("x\n"), "x\n"), "--- a/f\n+++ b/f\n");
    }
}
