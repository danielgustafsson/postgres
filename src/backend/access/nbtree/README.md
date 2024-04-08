src/backend/access/nbtree/README

Btree Indexing
==============

This directory contains a correct implementation of Lehman and Yao's
high-concurrency B-tree management algorithm (P. Lehman and S. Yao,
Efficient Locking for Concurrent Operations on B-Trees, ACM Transactions
on Database Systems, Vol 6, No. 4, December 1981, pp 650-670).  We also
use a simplified version of the deletion logic described in Lanin and
Shasha (V. Lanin and D. Shasha, A Symmetric Concurrent B-Tree Algorithm,
Proceedings of 1986 Fall Joint Computer Conference, pp 380-389).

The basic Lehman & Yao Algorithm
--------------------------------

Compared to a classic B-tree, L&Y adds a right-link pointer to each page,
to the page's right sibling.  It also adds a "high key" to each page, which
is an upper bound on the keys that are allowed on that page.  These two
additions make it possible to detect a concurrent page split, which allows
the tree to be searched without holding any read locks (except to keep a
single page from being modified while reading it).

When a search follows a downlink to a child page, it compares the page's
high key with the search key.  If the search key is greater than the high
key, the page must've been split concurrently, and you must follow the
right-link to find the new page containing the key range you're looking
for.  This might need to be repeated, if the page has been split more than
once.

Lehman and Yao talk about alternating "separator" keys and downlinks in
internal pages rather than tuples or records.  We use the term "pivot"
tuple to refer to tuples which don't point to heap tuples, that are used
only for tree navigation.  All tuples on non-leaf pages and high keys on
leaf pages are pivot tuples.  Since pivot tuples are only used to represent
which part of the key space belongs on each page, they can have attribute
values copied from non-pivot tuples that were deleted and killed by VACUUM
some time ago.  A pivot tuple may contain a "separator" key and downlink,
just a separator key (i.e. the downlink value is implicitly undefined), or
just a downlink (i.e. all attributes are truncated away).

The requirement that all btree keys be unique is satisfied by treating heap
TID as a tiebreaker attribute.  Logical duplicates are sorted in heap TID
order.  This is necessary because Lehman and Yao also require that the key
range for a subtree S is described by Ki < v <= Ki+1 where Ki and Ki+1 are
the adjacent keys in the parent page (Ki must be _strictly_ less than v,
which is assured by having reliably unique keys).  Keys are always unique
on their level, with the exception of a leaf page's high key, which can be
fully equal to the last item on the page.

The Postgres implementation of suffix truncation must make sure that the
Lehman and Yao invariants hold, and represents that absent/truncated
attributes in pivot tuples have the sentinel value "minus infinity".  The
later section on suffix truncation will be helpful if it's unclear how the
Lehman & Yao invariants work with a real world example.

Differences to the Lehman & Yao algorithm
-----------------------------------------

We have made the following changes in order to incorporate the L&Y algorithm
into Postgres:

Lehman and Yao don't require read locks, but assume that in-memory
copies of tree pages are unshared.  Postgres shares in-memory buffers
among backends.  As a result, we do page-level read locking on btree
pages in order to guarantee that no record is modified while we are
examining it.  This reduces concurrency but guarantees correct
behavior.

We support the notion of an ordered "scan" of an index as well as
insertions, deletions, and simple lookups.  A scan in the forward
direction is no problem, we just use the right-sibling pointers that
L&Y require anyway.  (Thus, once we have descended the tree to the
correct start point for the scan, the scan looks only at leaf pages
and never at higher tree levels.)  To support scans in the backward
direction, we also store a "left sibling" link much like the "right
sibling".  (This adds an extra step to the L&Y split algorithm: while
holding the write lock on the page being split, we also lock its former
right sibling to update that page's left-link.  This is safe since no
writer of that page can be interested in acquiring a write lock on our
page.)  A backwards scan has one additional bit of complexity: after
following the left-link we must account for the possibility that the
left sibling page got split before we could read it.  So, we have to
move right until we find a page whose right-link matches the page we
came from.  (Actually, it's even harder than that; see page deletion
discussion below.)

Page read locks are held only for as long as a scan is examining a page.
To minimize lock/unlock traffic, an index scan always searches a leaf page
to identify all the matching items at once, copying their heap tuple IDs
into backend-local storage.  The heap tuple IDs are then processed while
not holding any page lock within the index.  We do continue to hold a pin
on the leaf page in some circumstances, to protect against concurrent
deletions (see below).  In this state the scan is effectively stopped
"between" pages, either before or after the page it has pinned.  This is
safe in the presence of concurrent insertions and even page splits, because
items are never moved across pre-existing page boundaries --- so the scan
cannot miss any items it should have seen, nor accidentally return the same
item twice.  The scan must remember the page's right-link at the time it
was scanned, since that is the page to move right to; if we move right to
the current right-link then we'd re-scan any items moved by a page split.
We don't similarly remember the left-link, since it's best to use the most
up-to-date left-link when trying to move left (see detailed move-left
algorithm below).

In most cases we release our lock and pin on a page before attempting
to acquire pin and lock on the page we are moving to.  In a few places
it is necessary to lock the next page before releasing the current one.
This is safe when moving right or up, but not when moving left or down
(else we'd create the possibility of deadlocks).

Lehman and Yao fail to discuss what must happen when the root page
becomes full and must be split.  Our implementation is to split the
root in the same way that any other page would be split, then construct
a new root page holding pointers to both of the resulting pages (which
now become siblings on the next level of the tree).  The new root page
is then installed by altering the root pointer in the meta-data page (see
below).  This works because the root is not treated specially in any
other way --- in particular, searches will move right using its link
pointer if the link is set.  Therefore, searches will find the data
that's been moved into the right sibling even if they read the meta-data
page before it got updated.  This is the same reasoning that makes a
split of a non-root page safe.  The locking considerations are similar too.

When an inserter recurses up the tree, splitting internal pages to insert
links to pages inserted on the level below, it is possible that it will
need to access a page above the level that was the root when it began its
descent (or more accurately, the level that was the root when it read the
meta-data page).  In this case the stack it made while descending does not
help for finding the correct page.  When this happens, we find the correct
place by re-descending the tree until we reach the level one above the
level we need to insert a link to, and then moving right as necessary.
(Typically this will take only two fetches, the meta-data page and the new
root, but in principle there could have been more than one root split
since we saw the root.  We can identify the correct tree level by means of
the level numbers stored in each page.  The situation is rare enough that
we do not need a more efficient solution.)

Lehman and Yao must couple/chain locks as part of moving right when
relocating a child page's downlink during an ascent of the tree.  This is
the only point where Lehman and Yao have to simultaneously hold three
locks (a lock on the child, the original parent, and the original parent's
right sibling).  We don't need to couple internal page locks for pages on
the same level, though.  We match a child's block number to a downlink
from a pivot tuple one level up, whereas Lehman and Yao match on the
separator key associated with the downlink that was followed during the
initial descent.  We can release the lock on the original parent page
before acquiring a lock on its right sibling, since there is never any
need to deal with the case where the separator key that we must relocate
becomes the original parent's high key.  Lanin and Shasha don't couple
locks here either, though they also don't couple locks between levels
during ascents.  They are willing to "wait and try again" to avoid races.
Their algorithm is optimistic, which means that "an insertion holds no
more than one write lock at a time during its ascent".  We more or less
stick with Lehman and Yao's approach of conservatively coupling parent and
child locks when ascending the tree, since it's far simpler.

Lehman and Yao assume fixed-size keys, but we must deal with
variable-size keys.  Therefore there is not a fixed maximum number of
keys per page; we just stuff in as many as will fit.  When we split a
page, we try to equalize the number of bytes, not items, assigned to
pages (though suffix truncation is also considered).  Note we must include
the incoming item in this calculation, otherwise it is possible to find
that the incoming item doesn't fit on the split page where it needs to go!

Deleting index tuples during VACUUM
-----------------------------------

Before deleting a leaf item, we get a full cleanup lock on the target
page, so that no other backend has a pin on the page when the deletion
starts.  This is not necessary for correctness in terms of the btree index
operations themselves; as explained above, index scans logically stop
"between" pages and so can't lose their place.  The reason we do it is to
provide an interlock between VACUUM and index scans that are not prepared
to deal with concurrent TID recycling when visiting the heap.  Since only
VACUUM can ever mark pointed-to items LP_UNUSED in the heap, and since
this only ever happens _after_ btbulkdelete returns, having index scans
hold on to the pin (used when reading from the leaf page) until _after_
they're done visiting the heap (for TIDs from pinned leaf page) prevents
concurrent TID recycling.  VACUUM cannot get a conflicting cleanup lock
until the index scan is totally finished processing its leaf page.

This approach is fairly coarse, so we avoid it whenever possible.  In
practice most index scans won't hold onto their pin, and so won't block
VACUUM.  These index scans must deal with TID recycling directly, which is
more complicated and not always possible.  See later section on making
concurrent TID recycling safe.

Opportunistic index tuple deletion performs almost the same page-level
modifications while only holding an exclusive lock.  This is safe because
there is no question of TID recycling taking place later on -- only VACUUM
can make TIDs recyclable.  See also simple deletion and bottom-up
deletion, below.

Because a pin is not always held, and a page can be split even while
someone does hold a pin on it, it is possible that an indexscan will
return items that are no longer stored on the page it has a pin on, but
rather somewhere to the right of that page.  To ensure that VACUUM can't
prematurely make TIDs recyclable in this scenario, we require btbulkdelete
to obtain a cleanup lock on every leaf page in the index, even pages that
don't contain any deletable tuples.  Note that this requirement does not
say that btbulkdelete must visit the pages in any particular order.

VACUUM's linear scan, concurrent page splits
--------------------------------------------

VACUUM accesses the index by doing a linear scan to search for deletable
TIDs, while considering the possibility of deleting empty pages in
passing.  This is in physical/block order, not logical/keyspace order.
The tricky part of this is avoiding missing any deletable tuples in the
presence of concurrent page splits: a page split could easily move some
tuples from a page not yet passed over by the sequential scan to a
lower-numbered page already passed over.

To implement this, we provide a "vacuum cycle ID" mechanism that makes it
possible to determine whether a page has been split since the current
btbulkdelete cycle started.  If btbulkdelete finds a page that has been
split since it started, and has a right-link pointing to a lower page
number, then it temporarily suspends its sequential scan and visits that
page instead.  It must continue to follow right-links and vacuum dead
tuples until reaching a page that either hasn't been split since
btbulkdelete started, or is above the location of the outer sequential
scan.  Then it can resume the sequential scan.  This ensures that all
tuples are visited.  It may be that some tuples are visited twice, but
that has no worse effect than an inaccurate index tuple count (and we
can't guarantee an accurate count anyway in the face of concurrent
activity).  Note that this still works if the has-been-recently-split test
has a small probability of false positives, so long as it never gives a
false negative.  This makes it possible to implement the test with a small
counter value stored on each index page.

Deleting entire pages during VACUUM
-----------------------------------

We consider deleting an entire page from the btree only when it's become
completely empty of items.  (Merging partly-full pages would allow better
space reuse, but it seems impractical to move existing data items left or
right to make this happen --- a scan moving in the opposite direction
might miss the items if so.)  Also, we *never* delete the rightmost page
on a tree level (this restriction simplifies the traversal algorithms, as
explained below).  Page deletion always begins from an empty leaf page.  An
internal page can only be deleted as part of deleting an entire subtree.
This is always a "skinny" subtree consisting of a "chain" of internal pages
plus a single leaf page.  There is one page on each level of the subtree,
and each level/page covers the same key space.

Deleting a leaf page is a two-stage process.  In the first stage, the page
is unlinked from its parent, and marked as half-dead.  The parent page must
be found using the same type of search as used to find the parent during an
insertion split.  We lock the target and the parent pages, change the
target's downlink to point to the right sibling, and remove its old
downlink.  This causes the target page's key space to effectively belong to
its right sibling.  (Neither the left nor right sibling pages need to
change their "high key" if any; so there is no problem with possibly not
having enough space to replace a high key.)  At the same time, we mark the
target page as half-dead, which causes any subsequent searches to ignore it
and move right (or left, in a backwards scan).  This leaves the tree in a
similar state as during a page split: the page has no downlink pointing to
it, but it's still linked to its siblings.

(Note: Lanin and Shasha prefer to make the key space move left, but their
argument for doing so hinges on not having left-links, which we have
anyway.  So we simplify the algorithm by moving the key space right.  This
is only possible because we don't match on a separator key when ascending
the tree during a page split, unlike Lehman and Yao/Lanin and Shasha -- it
doesn't matter if the downlink is re-found in a pivot tuple whose separator
key does not match the one encountered when inserter initially descended
the tree.)

To preserve consistency on the parent level, we cannot merge the key space
of a page into its right sibling unless the right sibling is a child of
the same parent --- otherwise, the parent's key space assignment changes
too, meaning we'd have to make bounding-key updates in its parent, and
perhaps all the way up the tree.  Since we can't possibly do that
atomically, we forbid this case.  That means that the rightmost child of a
parent node can't be deleted unless it's the only remaining child, in which
case we will delete the parent too (see below).

In the second-stage, the half-dead leaf page is unlinked from its siblings.
We first lock the left sibling (if any) of the target, the target page
itself, and its right sibling (there must be one) in that order.  Then we
update the side-links in the siblings, and mark the target page deleted.

When we're about to delete the last remaining child of a parent page, things
are slightly more complicated.  In the first stage, we leave the immediate
parent of the leaf page alone, and remove the downlink to the parent page
instead, from the grandparent.  If it's the last child of the grandparent
too, we recurse up until we find a parent with more than one child, and
remove the downlink of that page.  The leaf page is marked as half-dead, and
the block number of the page whose downlink was removed is stashed in the
half-dead leaf page.  This leaves us with a chain of internal pages, with
one downlink each, leading to the half-dead leaf page, and no downlink
pointing to the topmost page in the chain.

While we recurse up to find the topmost parent in the chain, we keep the
leaf page locked, but don't need to hold locks on the intermediate pages
between the leaf and the topmost parent -- insertions into upper tree levels
happen only as a result of splits of child pages, and that can't happen as
long as we're keeping the leaf locked.  The internal pages in the chain
cannot acquire new children afterwards either, because the leaf page is
marked as half-dead and won't be split.

Removing the downlink to the top of the to-be-deleted subtree/chain
effectively transfers the key space to the right sibling for all the
intermediate levels too, in one atomic operation.  A concurrent search might
still visit the intermediate pages, but it will move right when it reaches
the half-dead page at the leaf level.  In particular, the search will move to
the subtree to the right of the half-dead leaf page/to-be-deleted subtree,
since the half-dead leaf page's right sibling must be a "cousin" page, not a
"true" sibling page (or a second cousin page when the to-be-deleted chain
starts at leaf page's grandparent page, and so on).

In the second stage, the topmost page in the chain is unlinked from its
siblings, and the half-dead leaf page is updated to point to the next page
down in the chain.  This is repeated until there are no internal pages left
in the chain.  Finally, the half-dead leaf page itself is unlinked from its
siblings.

A deleted page cannot be recycled immediately, since there may be other
processes waiting to reference it (ie, search processes that just left the
parent, or scans moving right or left from one of the siblings).  These
processes must be able to observe a deleted page for some time after the
deletion operation, in order to be able to at least recover from it (they
recover by moving right, as with concurrent page splits).  Searchers never
have to worry about concurrent page recycling.

See "Placing deleted pages in the FSM" section below for a description of
when and how deleted pages become safe for VACUUM to make recyclable.

Page deletion and backwards scans
---------------------------------

Moving left in a backward scan is complicated because we must consider
the possibility that the left sibling was just split (meaning we must find
the rightmost page derived from the left sibling), plus the possibility
that the page we were just on has now been deleted and hence isn't in the
sibling chain at all anymore.  So the move-left algorithm becomes:

0. Remember the page we are on as the "original page".
1. Follow the original page's left-link (we're done if this is zero).
2. If the current page is live and its right-link matches the "original
   page", we are done.
3. Otherwise, move right one or more times looking for a live page whose
   right-link matches the "original page".  If found, we are done.  (In
   principle we could scan all the way to the right end of the index, but
   in practice it seems better to give up after a small number of tries.
   It's unlikely the original page's sibling split more than a few times
   while we were in flight to it; if we do not find a matching link in a
   few tries, then most likely the original page is deleted.)
4. Return to the "original page".  If it is still live, return to step 1
   (we guessed wrong about it being deleted, and should restart with its
   current left-link).  If it is dead, move right until a non-dead page
   is found (there must be one, since rightmost pages are never deleted),
   mark that as the new "original page", and return to step 1.

This algorithm is correct because the live page found by step 4 will have
the same left keyspace boundary as the page we started from.  Therefore,
when we ultimately exit, it must be on a page whose right keyspace
boundary matches the left boundary of where we started --- which is what
we need to be sure we don't miss or re-scan any items.

Page deletion and tree height
-----------------------------

Because we never delete the rightmost page of any level (and in particular
never delete the root), it's impossible for the height of the tree to
decrease.  After massive deletions we might have a scenario in which the
tree is "skinny", with several single-page levels below the root.
Operations will still be correct in this case, but we'd waste cycles
descending through the single-page levels.  To handle this we use an idea
from Lanin and Shasha: we keep track of the "fast root" level, which is
the lowest single-page level.  The meta-data page keeps a pointer to this
level as well as the true root.  All ordinary operations initiate their
searches at the fast root not the true root.  When we split a page that is
alone on its level or delete the next-to-last page on a level (both cases
are easily detected), we have to make sure that the fast root pointer is
adjusted appropriately.  In the split case, we do this work as part of the
atomic update for the insertion into the parent level; in the delete case
as part of the atomic update for the delete (either way, the metapage has
to be the last page locked in the update to avoid deadlock risks).  This
avoids race conditions if two such operations are executing concurrently.

Placing deleted pages in the FSM
--------------------------------

Recycling a page is decoupled from page deletion.  A deleted page can only
be put in the FSM to be recycled once there is no possible scan or search
that has a reference to it; until then, it must stay in place with its
sibling links undisturbed, as a tombstone that allows concurrent searches
to detect and then recover from concurrent deletions (which are rather
like concurrent page splits to searchers).  This design is an
implementation of what Lanin and Shasha call "the drain technique".

We implement the technique by waiting until all active snapshots and
registered snapshots as of the page deletion are gone; which is overly
strong, but is simple to implement within Postgres.  When marked fully
dead, a deleted page is labeled with the next-transaction counter value.
VACUUM can reclaim the page for re-use when the stored XID is guaranteed
to be "visible to everyone".  As collateral damage, we wait for snapshots
taken until the next transaction to allocate an XID commits.  We also wait
for running XIDs with no snapshots.

Prior to PostgreSQL 14, VACUUM would only place _old_ deleted pages that
it encounters during its linear scan (pages deleted by a previous VACUUM
operation) in the FSM.  Newly deleted pages were never placed in the FSM,
because that was assumed to _always_ be unsafe.  That assumption was
unnecessarily pessimistic in practice, though -- it often doesn't take
very long for newly deleted pages to become safe to place in the FSM.
There is no truly principled way to predict when deleted pages will become
safe to place in the FSM for recycling -- it might become safe almost
immediately (long before the current VACUUM completes), or it might not
even be safe by the time the next VACUUM takes place.  Recycle safety is
purely a question of maintaining the consistency (or at least the apparent
consistency) of a physical data structure.  The state within the backend
running VACUUM is simply not relevant.

PostgreSQL 14 added the ability for VACUUM to consider if it's possible to
recycle newly deleted pages at the end of the full index scan where the
page deletion took place.  It is convenient to check if it's safe at that
point.  This does require that VACUUM keep around a little bookkeeping
information about newly deleted pages, but that's very cheap.  Using
in-memory state for this avoids the need to revisit newly deleted pages a
second time later on -- we can just use safexid values from the local
bookkeeping state to determine recycle safety in a deferred fashion.

The need for additional FSM indirection after a page deletion operation
takes place is a natural consequence of the highly permissive rules for
index scans with Lehman and Yao's design.  In general an index scan
doesn't have to hold a lock or even a pin on any page when it descends the
tree (nothing that you'd usually think of as an interlock is held "between
levels").  At the same time, index scans cannot be allowed to land on a
truly unrelated page due to concurrent recycling (not to be confused with
concurrent deletion), because that results in wrong answers to queries.
Simpler approaches to page deletion that don't need to defer recycling are
possible, but none seem compatible with Lehman and Yao's design.

Placing an already-deleted page in the FSM to be recycled when needed
doesn't actually change the state of the page.  The page will be changed
whenever it is subsequently taken from the FSM for reuse.  The deleted
page's contents will be overwritten by the split operation (it will become
the new right sibling page).

Making concurrent TID recycling safe
------------------------------------

As explained in the earlier section about deleting index tuples during
VACUUM, we implement a locking protocol that allows individual index scans
to avoid concurrent TID recycling.  Index scans opt-out (and so drop their
leaf page pin when visiting the heap) whenever it's safe to do so, though.
Dropping the pin early is useful because it avoids blocking progress by
VACUUM.  This is particularly important with index scans used by cursors,
since idle cursors sometimes stop for relatively long periods of time.  In
extreme cases, a client application may hold on to an idle cursors for
hours or even days.  Blocking VACUUM for that long could be disastrous.

Index scans that don't hold on to a buffer pin are protected by holding an
MVCC snapshot instead.  This more limited interlock prevents wrong answers
to queries, but it does not prevent concurrent TID recycling itself (only
holding onto the leaf page pin while accessing the heap ensures that).

Index-only scans can never drop their buffer pin, since they are unable to
tolerate having a referenced TID become recyclable.  Index-only scans
typically just visit the visibility map (not the heap proper), and so will
not reliably notice that any stale TID reference (for a TID that pointed
to a dead-to-all heap item at first) was concurrently marked LP_UNUSED in
the heap by VACUUM.  This could easily allow VACUUM to set the whole heap
page to all-visible in the visibility map immediately afterwards.  An MVCC
snapshot is only sufficient to avoid problems during plain index scans
because they must access granular visibility information from the heap
proper.  A plain index scan will even recognize LP_UNUSED items in the
heap (items that could be recycled but haven't been just yet) as "not
visible" -- even when the heap page is generally considered all-visible.

LP_DEAD setting of index tuples by the kill_prior_tuple optimization
(described in full in simple deletion, below) is also more complicated for
index scans that drop their leaf page pins.  We must be careful to avoid
LP_DEAD-marking any new index tuple that looks like a known-dead index
tuple because it happens to share the same TID, following concurrent TID
recycling.  It's just about possible that some other session inserted a
new, unrelated index tuple, on the same leaf page, which has the same
original TID.  It would be totally wrong to LP_DEAD-set this new,
unrelated index tuple.

We handle this kill_prior_tuple race condition by having affected index
scans conservatively assume that any change to the leaf page at all
implies that it was reached by btbulkdelete in the interim period when no
buffer pin was held.  This is implemented by not setting any LP_DEAD bits
on the leaf page at all when the page's LSN has changed.  (That won't work
with an unlogged index, so for now we don't ever apply the "don't hold
onto pin" optimization there.)

Fastpath For Index Insertion
----------------------------

We optimize for a common case of insertion of increasing index key
values by caching the last page to which this backend inserted the last
value, if this page was the rightmost leaf page. For the next insert, we
can then quickly check if the cached page is still the rightmost leaf
page and also the correct place to hold the current value. We can avoid
the cost of walking down the tree in such common cases.

The optimization works on the assumption that there can only be one
non-ignorable leaf rightmost page, and so not even a visible-to-everyone
style interlock is required.  We cannot fail to detect that our hint was
invalidated, because there can only be one such page in the B-Tree at
any time. It's possible that the page will be deleted and recycled
without a backend's cached page also being detected as invalidated, but
only when we happen to recycle a block that once again gets recycled as the
rightmost leaf page.

Simple deletion
---------------

If a process visits a heap tuple and finds that it's dead and removable
(ie, dead to all open transactions, not only that process), then we can
return to the index and mark the corresponding index entry "known dead",
allowing subsequent index scans to skip visiting the heap tuple.  The
"known dead" marking works by setting the index item's lp_flags state
to LP_DEAD.  This is currently only done in plain indexscans, not bitmap
scans, because only plain scans visit the heap and index "in sync" and so
there's not a convenient way to do it for bitmap scans.  Note also that
LP_DEAD bits are often set when checking a unique index for conflicts on
insert (this is simpler because it takes place when we hold an exclusive
lock on the leaf page).

Once an index tuple has been marked LP_DEAD it can actually be deleted
from the index immediately; since index scans only stop "between" pages,
no scan can lose its place from such a deletion.  We separate the steps
because we allow LP_DEAD to be set with only a share lock (it's like a
hint bit for a heap tuple), but physically deleting tuples requires an
exclusive lock.  We also need to generate a snapshotConflictHorizon for
each deletion operation's WAL record, which requires additional
coordinating with the tableam when the deletion actually takes place.
(snapshotConflictHorizon value may be used to generate a conflict during
subsequent REDO of the record by a standby.)

Delaying and batching index tuple deletion like this enables a further
optimization: opportunistic checking of "extra" nearby index tuples
(tuples that are not LP_DEAD-set) when they happen to be very cheap to
check in passing (because we already know that the tableam will be
visiting their table block to generate a snapshotConflictHorizon).  Any
index tuples that turn out to be safe to delete will also be deleted.
Simple deletion will behave as if the extra tuples that actually turn
out to be delete-safe had their LP_DEAD bits set right from the start.

Deduplication can also prevent a page split, but index tuple deletion is
our preferred approach.  Note that posting list tuples can only have
their LP_DEAD bit set when every table TID within the posting list is
known dead.  This isn't much of a problem in practice because LP_DEAD
bits are just a starting point for deletion.  What really matters is
that _some_ deletion operation that targets related nearby-in-table TIDs
takes place at some point before the page finally splits.  That's all
that's required for the deletion process to perform granular removal of
groups of dead TIDs from posting list tuples (without the situation ever
being allowed to get out of hand).

Bottom-Up deletion
------------------

We attempt to delete whatever duplicates happen to be present on the page
when the duplicates are suspected to be caused by version churn from
successive UPDATEs.  This only happens when we receive an executor hint
indicating that optimizations like heapam's HOT have not worked out for
the index -- the incoming tuple must be a logically unchanged duplicate
which is needed for MVCC purposes, suggesting that that might well be the
dominant source of new index tuples on the leaf page in question.  (Also,
bottom-up deletion is triggered within unique indexes in cases with
continual INSERT and DELETE related churn, since that is easy to detect
without any external hint.)

Simple deletion will already have failed to prevent a page split when a
bottom-up deletion pass takes place (often because no LP_DEAD bits were
ever set on the page).  The two mechanisms have closely related
implementations.  The same WAL records are used for each operation, and
the same tableam infrastructure is used to determine what TIDs/tuples are
actually safe to delete.  The implementations only differ in how they pick
TIDs to consider for deletion, and whether or not the tableam will give up
before accessing all table blocks (bottom-up deletion lives with the
uncertainty of its success by keeping the cost of failure low).  Even
still, the two mechanisms are clearly distinct at the conceptual level.

Bottom-up index deletion is driven entirely by heuristics (whereas simple
deletion is guaranteed to delete at least those index tuples that are
already LP_DEAD marked -- there must be at least one).  We have no
certainty that we'll find even one index tuple to delete.  That's why we
closely cooperate with the tableam to keep the costs it pays in balance
with the benefits we receive.  The interface that we use for this is
described in detail in access/tableam.h.

Bottom-up index deletion can be thought of as a backstop mechanism against
unnecessary version-driven page splits.  It is based in part on an idea
from generational garbage collection: the "generational hypothesis".  This
is the empirical observation that "most objects die young".  Within
nbtree, new index tuples often quickly appear in the same place, and then
quickly become garbage.  There can be intense concentrations of garbage in
relatively few leaf pages with certain workloads (or there could be in
earlier versions of PostgreSQL without bottom-up index deletion, at
least).  See doc/src/sgml/btree.sgml for a high-level description of the
design principles behind bottom-up index deletion in nbtree, including
details of how it complements VACUUM.

We expect to find a reasonably large number of tuples that are safe to
delete within each bottom-up pass.  If we don't then we won't need to
consider the question of bottom-up deletion for the same leaf page for
quite a while (usually because the page splits, which resolves the
situation for the time being).  We expect to perform regular bottom-up
deletion operations against pages that are at constant risk of unnecessary
page splits caused only by version churn.  When the mechanism works well
we'll constantly be "on the verge" of having version-churn-driven page
splits, but never actually have even one.

Our duplicate heuristics work well despite being fairly simple.
Unnecessary page splits only occur when there are truly pathological
levels of version churn (in theory a small amount of version churn could
make a page split occur earlier than strictly necessary, but that's pretty
harmless).  We don't have to understand the underlying workload; we only
have to understand the general nature of the pathology that we target.
Version churn is easy to spot when it is truly pathological.  Affected
leaf pages are fairly homogeneous.

WAL Considerations
------------------

The insertion and deletion algorithms in themselves don't guarantee btree
consistency after a crash.  To provide robustness, we depend on WAL
replay.  A single WAL entry is effectively an atomic action --- we can
redo it from the log if it fails to complete.

Ordinary item insertions (that don't force a page split) are of course
single WAL entries, since they only affect one page.  The same for
leaf-item deletions (if the deletion brings the leaf page to zero items,
it is now a candidate to be deleted, but that is a separate action).

An insertion that causes a page split is logged as a single WAL entry for
the changes occurring on the insertion's level --- including update of the
right sibling's left-link --- followed by a second WAL entry for the
insertion on the parent level (which might itself be a page split, requiring
an additional insertion above that, etc).

For a root split, the follow-on WAL entry is a "new root" entry rather than
an "insertion" entry, but details are otherwise much the same.

Because splitting involves multiple atomic actions, it's possible that the
system crashes between splitting a page and inserting the downlink for the
new half to the parent.  After recovery, the downlink for the new page will
be missing.  The search algorithm works correctly, as the page will be found
by following the right-link from its left sibling, although if a lot of
downlinks in the tree are missing, performance will suffer.  A more serious
consequence is that if the page without a downlink gets split again, the
insertion algorithm will fail to find the location in the parent level to
insert the downlink.

Our approach is to create any missing downlinks on-the-fly, when searching
the tree for a new insertion.  It could be done during searches, too, but
it seems best not to put any extra updates in what would otherwise be a
read-only operation (updating is not possible in hot standby mode anyway).
It would seem natural to add the missing downlinks in VACUUM, but since
inserting a downlink might require splitting a page, it might fail if you
run out of disk space.  That would be bad during VACUUM - the reason for
running VACUUM in the first place might be that you run out of disk space,
and now VACUUM won't finish because you're out of disk space.  In contrast,
an insertion can require enlarging the physical file anyway.  There is one
minor exception: VACUUM finishes interrupted splits of internal pages when
deleting their children.  This allows the code for re-finding parent items
to be used by both page splits and page deletion.

To identify missing downlinks, when a page is split, the left page is
flagged to indicate that the split is not yet complete (INCOMPLETE_SPLIT).
When the downlink is inserted to the parent, the flag is cleared atomically
with the insertion.  The child page is kept locked until the insertion in
the parent is finished and the flag in the child cleared, but can be
released immediately after that, before recursing up the tree if the parent
also needs to be split.  This ensures that incompletely split pages should
not be seen under normal circumstances; only if insertion to the parent
has failed for some reason. (It's also possible for a reader to observe
a page with the incomplete split flag set during recovery; see later
section on "Scans during Recovery" for details.)

We flag the left page, even though it's the right page that's missing the
downlink, because it's more convenient to know already when following the
right-link from the left page to the right page that it will need to have
its downlink inserted to the parent.

When splitting a non-root page that is alone on its level, the required
metapage update (of the "fast root" link) is performed and logged as part
of the insertion into the parent level.  When splitting the root page, the
metapage update is handled as part of the "new root" action.

Each step in page deletion is logged as a separate WAL entry: marking the
leaf as half-dead and removing the downlink is one record, and unlinking a
page is a second record.  If vacuum is interrupted for some reason, or the
system crashes, the tree is consistent for searches and insertions.  The
next VACUUM will find the half-dead leaf page and continue the deletion.

Before 9.4, we used to keep track of incomplete splits and page deletions
during recovery and finish them immediately at end of recovery, instead of
doing it lazily at the next insertion or vacuum.  However, that made the
recovery much more complicated, and only fixed the problem when crash
recovery was performed.  An incomplete split can also occur if an otherwise
recoverable error, like out-of-memory or out-of-disk-space, happens while
inserting the downlink to the parent.

Scans during Recovery
---------------------

nbtree indexes support read queries in Hot Standby mode. Every atomic
action/WAL record makes isolated changes that leave the tree in a
consistent state for readers. Readers lock pages according to the same
rules that readers follow on the primary. (Readers may have to move
right to recover from a "concurrent" page split or page deletion, just
like on the primary.)

However, there are a couple of differences in how pages are locked by
replay/the startup process as compared to the original write operation
on the primary. The exceptions involve page splits and page deletions.
The first phase and second phase of a page split are processed
independently during replay, since they are independent atomic actions.
We do not attempt to recreate the coupling of parent and child page
write locks that took place on the primary. This is safe because readers
never care about the incomplete split flag anyway. Holding on to an
extra write lock on the primary is only necessary so that a second
writer cannot observe the incomplete split flag before the first writer
finishes the split. If we let concurrent writers on the primary observe
an incomplete split flag on the same page, each writer would attempt to
complete the unfinished split, corrupting the parent page.  (Similarly,
replay of page deletion records does not hold a write lock on the target
leaf page throughout; only the primary needs to block out concurrent
writers that insert on to the page being deleted.)

WAL replay holds same-level locks in a way that matches the approach
taken during original execution, though. This prevent readers from
observing same-level inconsistencies. It's probably possible to be more
lax about how same-level locks are acquired during recovery (most kinds
of readers could still move right to recover if we didn't couple
same-level locks), but we prefer to be conservative here.

During recovery all index scans start with ignore_killed_tuples = false
and we never set kill_prior_tuple. We do this because the oldest xmin
on the standby server can be older than the oldest xmin on the primary
server, which means tuples can be marked LP_DEAD even when they are
still visible on the standby. We don't WAL log tuple LP_DEAD bits, but
they can still appear in the standby because of full page writes. So
we must always ignore them in standby, and that means it's not worth
setting them either.  (When LP_DEAD-marked tuples are eventually deleted
on the primary, the deletion is WAL-logged.  Queries that run on a
standby therefore get much of the benefit of any LP_DEAD setting that
takes place on the primary.)

Note that we talk about scans that are started during recovery. We go to
a little trouble to allow a scan to start during recovery and end during
normal running after recovery has completed. This is a key capability
because it allows running applications to continue while the standby
changes state into a normally running server.

The interlocking required to avoid returning incorrect results from
non-MVCC scans is not required on standby nodes. We still get a full
cleanup lock when replaying VACUUM records during recovery, but recovery
does not need to lock every leaf page (only those leaf pages that have
items to delete) -- that's sufficient to avoid breaking index-only scans
during recovery (see section above about making TID recycling safe). That
leaves concern only for plain index scans. (XXX: Not actually clear why
this is totally unnecessary during recovery.)

MVCC snapshot plain index scans are always safe, for the same reasons that
they're safe during original execution.  HeapTupleSatisfiesToast() doesn't
use MVCC semantics, though that's because it doesn't need to - if the main
heap row is visible then the toast rows will also be visible. So as long
as we follow a toast pointer from a visible (live) tuple the corresponding
toast rows will also be visible, so we do not need to recheck MVCC on
them.

Other Things That Are Handy to Know
-----------------------------------

Page zero of every btree is a meta-data page.  This page stores the
location of the root page --- both the true root and the current effective
root ("fast" root).  To avoid fetching the metapage for every single index
search, we cache a copy of the meta-data information in the index's
relcache entry (rd_amcache).  This is a bit ticklish since using the cache
implies following a root page pointer that could be stale.  However, a
backend following a cached pointer can sufficiently verify whether it
reached the intended page; either by checking the is-root flag when it
is going to the true root, or by checking that the page has no siblings
when going to the fast root.  At worst, this could result in descending
some extra tree levels if we have a cached pointer to a fast root that is
now above the real fast root.  Such cases shouldn't arise often enough to
be worth optimizing; and in any case we can expect a relcache flush will
discard the cached metapage before long, since a VACUUM that's moved the
fast root pointer can be expected to issue a statistics update for the
index.

The algorithm assumes we can fit at least three items per page
(a "high key" and two real data items).  Therefore it's unsafe
to accept items larger than 1/3rd page size.  Larger items would
work sometimes, but could cause failures later on depending on
what else gets put on their page.

"ScanKey" data structures are used in two fundamentally different ways
in this code, which we describe as "search" scankeys and "insertion"
scankeys.  A search scankey is the kind passed to btbeginscan() or
btrescan() from outside the btree code.  The sk_func pointers in a search
scankey point to comparison functions that return boolean, such as int4lt.
There might be more than one scankey entry for a given index column, or
none at all.  (We require the keys to appear in index column order, but
the order of multiple keys for a given column is unspecified.)  An
insertion scankey ("BTScanInsert" data structure) uses a similar
array-of-ScanKey data structure, but the sk_func pointers point to btree
comparison support functions (ie, 3-way comparators that return int4 values
interpreted as <0, =0, >0).  In an insertion scankey there is at most one
entry per index column.  There is also other data about the rules used to
locate where to begin the scan, such as whether or not the scan is a
"nextkey" scan.  Insertion scankeys are built within the btree code (eg, by
_bt_mkscankey()) and are used to locate the starting point of a scan, as
well as for locating the place to insert a new index tuple.  (Note: in the
case of an insertion scankey built from a search scankey or built from a
truncated pivot tuple, there might be fewer keys than index columns,
indicating that we have no constraints for the remaining index columns.)
After we have located the starting point of a scan, the original search
scankey is consulted as each index entry is sequentially scanned to decide
whether to return the entry and whether the scan can stop (see
_bt_checkkeys()).

Notes about suffix truncation
-----------------------------

We truncate away suffix key attributes that are not needed for a page high
key during a leaf page split.  The remaining attributes must distinguish
the last index tuple on the post-split left page as belonging on the left
page, and the first index tuple on the post-split right page as belonging
on the right page.  Tuples logically retain truncated key attributes,
though they implicitly have "negative infinity" as their value, and have no
storage overhead.  Since the high key is subsequently reused as the
downlink in the parent page for the new right page, suffix truncation makes
pivot tuples short.  INCLUDE indexes are guaranteed to have non-key
attributes truncated at the time of a leaf page split, but may also have
some key attributes truncated away, based on the usual criteria for key
attributes.  They are not a special case, since non-key attributes are
merely payload to B-Tree searches.

The goal of suffix truncation of key attributes is to improve index
fan-out.  The technique was first described by Bayer and Unterauer (R.Bayer
and K.Unterauer, Prefix B-Trees, ACM Transactions on Database Systems, Vol
2, No. 1, March 1977, pp 11-26).  The Postgres implementation is loosely
based on their paper.  Note that Postgres only implements what the paper
refers to as simple prefix B-Trees.  Note also that the paper assumes that
the tree has keys that consist of single strings that maintain the "prefix
property", much like strings that are stored in a suffix tree (comparisons
of earlier bytes must always be more significant than comparisons of later
bytes, and, in general, the strings must compare in a way that doesn't
break transitive consistency as they're split into pieces).  Suffix
truncation in Postgres currently only works at the whole-attribute
granularity, but it would be straightforward to invent opclass
infrastructure that manufactures a smaller attribute value in the case of
variable-length types, such as text.  An opclass support function could
manufacture the shortest possible key value that still correctly separates
each half of a leaf page split.

There is sophisticated criteria for choosing a leaf page split point.  The
general idea is to make suffix truncation effective without unduly
influencing the balance of space for each half of the page split.  The
choice of leaf split point can be thought of as a choice among points
*between* items on the page to be split, at least if you pretend that the
incoming tuple was placed on the page already (you have to pretend because
there won't actually be enough space for it on the page).  Choosing the
split point between two index tuples where the first non-equal attribute
appears as early as possible results in truncating away as many suffix
attributes as possible.  Evenly balancing space among each half of the
split is usually the first concern, but even small adjustments in the
precise split point can allow truncation to be far more effective.

Suffix truncation is primarily valuable because it makes pivot tuples
smaller, which delays splits of internal pages, but that isn't the only
reason why it's effective.  Even truncation that doesn't make pivot tuples
smaller due to alignment still prevents pivot tuples from being more
restrictive than truly necessary in how they describe which values belong
on which pages.

While it's not possible to correctly perform suffix truncation during
internal page splits, it's still useful to be discriminating when splitting
an internal page.  The split point that implies a downlink be inserted in
the parent that's the smallest one available within an acceptable range of
the fillfactor-wise optimal split point is chosen.  This idea also comes
from the Prefix B-Tree paper.  This process has much in common with what
happens at the leaf level to make suffix truncation effective.  The overall
effect is that suffix truncation tends to produce smaller, more
discriminating pivot tuples, especially early in the lifetime of the index,
while biasing internal page splits makes the earlier, smaller pivot tuples
end up in the root page, delaying root page splits.

Logical duplicates are given special consideration.  The logic for
selecting a split point goes to great lengths to avoid having duplicates
span more than one page, and almost always manages to pick a split point
between two user-key-distinct tuples, accepting a completely lopsided split
if it must.  When a page that's already full of duplicates must be split,
the fallback strategy assumes that duplicates are mostly inserted in
ascending heap TID order.  The page is split in a way that leaves the left
half of the page mostly full, and the right half of the page mostly empty.
The overall effect is that leaf page splits gracefully adapt to inserts of
large groups of duplicates, maximizing space utilization.  Note also that
"trapping" large groups of duplicates on the same leaf page like this makes
deduplication more efficient.  Deduplication can be performed infrequently,
without merging together existing posting list tuples too often.

Notes about deduplication
-------------------------

We deduplicate non-pivot tuples in non-unique indexes to reduce storage
overhead, and to avoid (or at least delay) page splits.  Note that the
goals for deduplication in unique indexes are rather different; see later
section for details.  Deduplication alters the physical representation of
tuples without changing the logical contents of the index, and without
adding overhead to read queries.  Non-pivot tuples are merged together
into a single physical tuple with a posting list (a simple array of heap
TIDs with the standard item pointer format).  Deduplication is always
applied lazily, at the point where it would otherwise be necessary to
perform a page split.  It occurs only when LP_DEAD items have been
removed, as our last line of defense against splitting a leaf page
(bottom-up index deletion may be attempted first, as our second last line
of defense).  We can set the LP_DEAD bit with posting list tuples, though
only when all TIDs are known dead.

Our lazy approach to deduplication allows the page space accounting used
during page splits to have absolutely minimal special case logic for
posting lists.  Posting lists can be thought of as extra payload that
suffix truncation will reliably truncate away as needed during page
splits, just like non-key columns from an INCLUDE index tuple.
Incoming/new tuples can generally be treated as non-overlapping plain
items (though see section on posting list splits for information about how
overlapping new/incoming items are really handled).

The representation of posting lists is almost identical to the posting
lists used by GIN, so it would be straightforward to apply GIN's varbyte
encoding compression scheme to individual posting lists.  Posting list
compression would break the assumptions made by posting list splits about
page space accounting (see later section), so it's not clear how
compression could be integrated with nbtree.  Besides, posting list
compression does not offer a compelling trade-off for nbtree, since in
general nbtree is optimized for consistent performance with many
concurrent readers and writers.  Compression would also make the deletion
of a subset of TIDs from a posting list slow and complicated, which would
be a big problem for workloads that depend heavily on bottom-up index
deletion.

A major goal of our lazy approach to deduplication is to limit the
performance impact of deduplication with random updates.  Even concurrent
append-only inserts of the same key value will tend to have inserts of
individual index tuples in an order that doesn't quite match heap TID
order.  Delaying deduplication minimizes page level fragmentation.

Deduplication in unique indexes
-------------------------------

Very often, the number of distinct values that can ever be placed on
almost any given leaf page in a unique index is fixed and permanent.  For
example, a primary key on an identity column will usually only have leaf
page splits caused by the insertion of new logical rows within the
rightmost leaf page.  If there is a split of a non-rightmost leaf page,
then the split must have been triggered by inserts associated with UPDATEs
of existing logical rows.  Splitting a leaf page purely to store multiple
versions is a false economy.  In effect, we're permanently degrading the
index structure just to absorb a temporary burst of duplicates.

Deduplication in unique indexes helps to prevent these pathological page
splits.  Storing duplicates in a space efficient manner is not the goal,
since in the long run there won't be any duplicates anyway.  Rather, we're
buying time for standard garbage collection mechanisms to run before a
page split is needed.

Unique index leaf pages only get a deduplication pass when an insertion
(that might have to split the page) observed an existing duplicate on the
page in passing.  This is based on the assumption that deduplication will
only work out when _all_ new insertions are duplicates from UPDATEs.  This
may mean that we miss an opportunity to delay a page split, but that's
okay because our ultimate goal is to delay leaf page splits _indefinitely_
(i.e. to prevent them altogether).  There is little point in trying to
delay a split that is probably inevitable anyway.  This allows us to avoid
the overhead of attempting to deduplicate with unique indexes that always
have few or no duplicates.

Note: Avoiding "unnecessary" page splits driven by version churn is also
the goal of bottom-up index deletion, which was added to PostgreSQL 14.
Bottom-up index deletion is now the preferred way to deal with this
problem (with all kinds of indexes, though especially with unique
indexes).  Still, deduplication can sometimes augment bottom-up index
deletion.  When deletion cannot free tuples (due to an old snapshot
holding up cleanup), falling back on deduplication provides additional
capacity.  Delaying the page split by deduplicating can allow a future
bottom-up deletion pass of the same page to succeed.

Posting list splits
-------------------

When the incoming tuple happens to overlap with an existing posting list,
a posting list split is performed.  Like a page split, a posting list
split resolves a situation where a new/incoming item "won't fit", while
inserting the incoming item in passing (i.e. as part of the same atomic
action).  It's possible (though not particularly likely) that an insert of
a new item on to an almost-full page will overlap with a posting list,
resulting in both a posting list split and a page split.  Even then, the
atomic action that splits the posting list also inserts the new item
(since page splits always insert the new item in passing).  Including the
posting list split in the same atomic action as the insert avoids problems
caused by concurrent inserts into the same posting list --  the exact
details of how we change the posting list depend upon the new item, and
vice-versa.  A single atomic action also minimizes the volume of extra
WAL required for a posting list split, since we don't have to explicitly
WAL-log the original posting list tuple.

Despite piggy-backing on the same atomic action that inserts a new tuple,
posting list splits can be thought of as a separate, extra action to the
insert itself (or to the page split itself).  Posting list splits
conceptually "rewrite" an insert that overlaps with an existing posting
list into an insert that adds its final new item just to the right of the
posting list instead.  The size of the posting list won't change, and so
page space accounting code does not need to care about posting list splits
at all.  This is an important upside of our design; the page split point
choice logic is very subtle even without it needing to deal with posting
list splits.

Only a few isolated extra steps are required to preserve the illusion that
the new item never overlapped with an existing posting list in the first
place: the heap TID of the incoming tuple has its TID replaced with the
rightmost/max heap TID from the existing/originally overlapping posting
list.  Similarly, the original incoming item's TID is relocated to the
appropriate offset in the posting list (we usually shift TIDs out of the
way to make a hole for it).  Finally, the posting-split-with-page-split
case must generate a new high key based on an imaginary version of the
original page that has both the final new item and the after-list-split
posting tuple (page splits usually just operate against an imaginary
version that contains the new item/item that won't fit).

This approach avoids inventing an "eager" atomic posting split operation
that splits the posting list without simultaneously finishing the insert
of the incoming item.  This alternative design might seem cleaner, but it
creates subtle problems for page space accounting.  In general, there
might not be enough free space on the page to split a posting list such
that the incoming/new item no longer overlaps with either posting list
half --- the operation could fail before the actual retail insert of the
new item even begins.  We'd end up having to handle posting list splits
that need a page split anyway.  Besides, supporting variable "split points"
while splitting posting lists won't actually improve overall space
utilization.

Notes About Data Representation
-------------------------------

The right-sibling link required by L&Y is kept in the page "opaque
data" area, as is the left-sibling link, the page level, and some flags.
The page level counts upwards from zero at the leaf level, to the tree
depth minus 1 at the root.  (Counting up from the leaves ensures that we
don't need to renumber any existing pages when splitting the root.)

The Postgres disk block data format (an array of items) doesn't fit
Lehman and Yao's alternating-keys-and-pointers notion of a disk page,
so we have to play some games.  (The alternating-keys-and-pointers
notion is important for internal page splits, which conceptually split
at the middle of an existing pivot tuple -- the tuple's "separator" key
goes on the left side of the split as the left side's new high key,
while the tuple's pointer/downlink goes on the right side as the
first/minus infinity downlink.)

On a page that is not rightmost in its tree level, the "high key" is
kept in the page's first item, and real data items start at item 2.
The link portion of the "high key" item goes unused.  A page that is
rightmost has no "high key" (it's implicitly positive infinity), so
data items start with the first item.  Putting the high key at the
left, rather than the right, may seem odd, but it avoids moving the
high key as we add data items.

On a leaf page, the data items are simply links to (TIDs of) tuples
in the relation being indexed, with the associated key values.

On a non-leaf page, the data items are down-links to child pages with
bounding keys.  The key in each data item is a strict lower bound for
keys on that child page, so logically the key is to the left of that
downlink.  The high key (if present) is the upper bound for the last
downlink.  The first data item on each such page has no lower bound
--- or lower bound of minus infinity, if you prefer.  The comparison
routines must treat it accordingly.  The actual key stored in the
item is irrelevant, and need not be stored at all.  This arrangement
corresponds to the fact that an L&Y non-leaf page has one more pointer
than key.  Suffix truncation's negative infinity attributes behave in
the same way.