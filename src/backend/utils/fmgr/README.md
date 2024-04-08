src/backend/utils/fmgr/README

Function Manager
================

[This file originally explained the transition from the V0 to the V1
interface.  Now it just explains some internals and rationale for the V1
interface, while the V0 interface has been removed.]

The V1 Function-Manager Interface
---------------------------------

The core of the design is data structures for representing the result of a
function lookup and for representing the parameters passed to a specific
function invocation.  (We want to keep function lookup separate from
function call, since many parts of the system apply the same function over
and over; the lookup overhead should be paid once per query, not once per
tuple.)


When a function is looked up in pg_proc, the result is represented as

	typedef struct
	{
	    PGFunction  fn_addr;    /* pointer to function or handler to be called */
	    Oid         fn_oid;     /* OID of function (NOT of handler, if any) */
	    short       fn_nargs;   /* number of input args (0..FUNC_MAX_ARGS) */
	    bool        fn_strict;  /* function is "strict" (NULL in => NULL out) */
	    bool        fn_retset;  /* function returns a set (over multiple calls) */
	    unsigned char fn_stats; /* collect stats if track_functions > this */
	    void       *fn_extra;   /* extra space for use by handler */
	    MemoryContext fn_mcxt;  /* memory context to store fn_extra in */
	    Node       *fn_expr;    /* expression parse tree for call, or NULL */
	} FmgrInfo;

For an ordinary built-in function, fn_addr is just the address of the C
routine that implements the function.  Otherwise it is the address of a
handler for the class of functions that includes the target function.
The handler can use the function OID and perhaps also the fn_extra slot
to find the specific code to execute.  (fn_oid = InvalidOid can be used
to denote a not-yet-initialized FmgrInfo struct.  fn_extra will always
be NULL when an FmgrInfo is first filled by the function lookup code, but
a function handler could set it to avoid making repeated lookups of its
own when the same FmgrInfo is used repeatedly during a query.)  fn_nargs
is the number of arguments expected by the function, fn_strict is its
strictness flag, and fn_retset shows whether it returns a set; all of
these values come from the function's pg_proc entry.  fn_stats is also
set up to control whether or not to track runtime statistics for calling
this function.

If the function is being called as part of a SQL expression, fn_expr will
point to the expression parse tree for the function call; this can be used
to extract parse-time knowledge about the actual arguments.  Note that this
field really is information about the arguments rather than information
about the function, but it's proven to be more convenient to keep it in
FmgrInfo than in FunctionCallInfoBaseData where it might more logically go.


During a call of a function, the following data structure is created
and passed to the function:

	typedef struct
	{
	    FmgrInfo   *flinfo;         /* ptr to lookup info used for this call */
	    Node       *context;        /* pass info about context of call */
	    Node       *resultinfo;     /* pass or return extra info about result */
	    Oid         fncollation;    /* collation for function to use */
	    bool        isnull;         /* function must set true if result is NULL */
	    short       nargs;          /* # arguments actually passed */
	    NullableDatum args[];       /* Arguments passed to function */
	} FunctionCallInfoBaseData;
	typedef FunctionCallInfoBaseData* FunctionCallInfo;

flinfo points to the lookup info used to make the call.  Ordinary functions
will probably ignore this field, but function class handlers will need it
to find out the OID of the specific function being called.

context is NULL for an "ordinary" function call, but may point to additional
info when the function is called in certain contexts.  (For example, the
trigger manager will pass information about the current trigger event here.)
Further details appear in "Function Call Contexts" below.

resultinfo is NULL when calling any function from which a simple Datum
result is expected.  It may point to some subtype of Node if the function
returns more than a Datum.  (For example, resultinfo is used when calling a
function that returns a set, as discussed below.)  Like the context field,
resultinfo is a hook for expansion; fmgr itself doesn't constrain the use
of the field.

fncollation is the input collation derived by the parser, or InvalidOid
when there are no inputs of collatable types or they don't share a common
collation.  This is effectively a hidden additional argument, which
collation-sensitive functions can use to determine their behavior.

nargs and args[] hold the arguments being passed to the function.
Notice that all the arguments passed to a function (as well as its result
value) will now uniformly be of type Datum.  As discussed below, callers
and callees should apply the standard Datum-to-and-from-whatever macros
to convert to the actual argument types of a particular function.  The
value in args[i].value is unspecified when args[i].isnull is true.

It is generally the responsibility of the caller to ensure that the
number of arguments passed matches what the callee is expecting; except
for callees that take a variable number of arguments, the callee will
typically ignore the nargs field and just grab values from args[].

The isnull field will be initialized to "false" before the call.  On
return from the function, isnull is the null flag for the function result:
if it is true the function's result is NULL, regardless of the actual
function return value.  Note that simple "strict" functions can ignore
both isnull and args[i].isnull, since they won't even get called when there
are any TRUE values in args[].isnull.

FunctionCallInfo replaces FmgrValues plus a bunch of ad-hoc parameter
conventions, global variables (fmgr_pl_finfo and CurrentTriggerData at
least), and other uglinesses.


Callees, whether they be individual functions or function handlers,
shall always have this signature:

	Datum function (FunctionCallInfo fcinfo);

which is represented by the typedef

	typedef Datum (*PGFunction) (FunctionCallInfo fcinfo);

The function is responsible for setting fcinfo->isnull appropriately
as well as returning a result represented as a Datum.  Note that since
all callees will now have exactly the same signature, and will be called
through a function pointer declared with exactly that signature, we
should have no portability or optimization problems.


Function Coding Conventions
---------------------------

Here are the proposed macros and coding conventions:

The definition of an fmgr-callable function will always look like

	Datum
	function_name(PG_FUNCTION_ARGS)
	{
		...
	}

"PG_FUNCTION_ARGS" just expands to "FunctionCallInfo fcinfo".  The main
reason for using this macro is to make it easy for scripts to spot function
definitions.  However, if we ever decide to change the calling convention
again, it might come in handy to have this macro in place.

A nonstrict function is responsible for checking whether each individual
argument is null or not, which it can do with PG_ARGISNULL(n) (which is
just "fcinfo->args[n].isnull").  It should avoid trying to fetch the value
of any argument that is null.

Both strict and nonstrict functions can return NULL, if needed, with

	PG_RETURN_NULL();

which expands to

	{ fcinfo->isnull = true; return (Datum) 0; }

Argument values are ordinarily fetched using code like

	int32	name = PG_GETARG_INT32(number);

For float4, float8, and int8, the PG_GETARG macros will hide whether the
types are pass-by-value or pass-by-reference.  For example, if float8 is
pass-by-reference then PG_GETARG_FLOAT8 expands to


	(* (float8 *) DatumGetPointer(fcinfo->args[number].value))

and would typically be called like this:

	float8  arg = PG_GETARG_FLOAT8(0);

For what are now historical reasons, the float-related typedefs and macros
express the type width in bytes (4 or 8), whereas we prefer to label the
widths of integer types in bits.

Non-null values are returned with a PG_RETURN_XXX macro of the appropriate
type.  For example, PG_RETURN_INT32 expands to

	return Int32GetDatum(x)

PG_RETURN_FLOAT4, PG_RETURN_FLOAT8, and PG_RETURN_INT64 hide whether their
data types are pass-by-value or pass-by-reference, by doing a palloc if
needed.

fmgr.h will provide PG_GETARG and PG_RETURN macros for all the basic data
types.  Modules or header files that define specialized SQL datatypes
(eg, timestamp) should define appropriate macros for those types, so that
functions manipulating the types can be coded in the standard style.

For non-primitive data types (particularly variable-length types) it won't
be very practical to hide the pass-by-reference nature of the data type,
so the PG_GETARG and PG_RETURN macros for those types won't do much more
than DatumGetPointer/PointerGetDatum plus the appropriate typecast (but see
TOAST discussion, below).  Functions returning such types will need to
palloc() their result space explicitly.  I recommend naming the GETARG and
RETURN macros for such types to end in "_P", as a reminder that they
produce or take a pointer.  For example, PG_GETARG_TEXT_P yields "text *".

When a function needs to access fcinfo->flinfo or one of the other auxiliary
fields of FunctionCallInfo, it should just do it.  I doubt that providing
syntactic-sugar macros for these cases is useful.


Support for TOAST-Able Data Types
---------------------------------

For TOAST-able data types, the PG_GETARG macro will deliver a de-TOASTed
data value.  There might be a few cases where the still-toasted value is
wanted, but the vast majority of cases want the de-toasted result, so
that will be the default.  To get the argument value without causing
de-toasting, use PG_GETARG_RAW_VARLENA_P(n).

Some functions require a modifiable copy of their input values.  In these
cases, it's silly to do an extra copy step if we copied the data anyway
to de-TOAST it.  Therefore, each toastable datatype has an additional
fetch macro, for example PG_GETARG_TEXT_P_COPY(n), which delivers a
guaranteed-fresh copy, combining this with the detoasting step if possible.

There is also a PG_FREE_IF_COPY(ptr,n) macro, which pfree's the given
pointer if and only if it is different from the original value of the n'th
argument.  This can be used to free the de-toasted value of the n'th
argument, if it was actually de-toasted.  Currently, doing this is not
necessary for the majority of functions because the core backend code
releases temporary space periodically, so that memory leaked in function
execution isn't a big problem.  However, as of 7.1 memory leaks in
functions that are called by index searches will not be cleaned up until
end of transaction.  Therefore, functions that are listed in pg_amop or
pg_amproc should be careful not to leak detoasted copies, and so these
functions do need to use PG_FREE_IF_COPY() for toastable inputs.

A function should never try to re-TOAST its result value; it should just
deliver an untoasted result that's been palloc'd in the current memory
context.  When and if the value is actually stored into a tuple, the
tuple toaster will decide whether toasting is needed.


Function Call Contexts
----------------------

If a caller passes a non-NULL pointer in fcinfo->context, it should point
to some subtype of Node; the particular kind of context is indicated by the
node type field.  (A callee should always check the node type, via IsA(),
before assuming it knows what kind of context is being passed.)  fmgr
itself puts no other restrictions on the use of this field.

Current uses of this convention include:

* Trigger functions are passed an instance of struct TriggerData,
containing information about the trigger context.  (The trigger function
does not receive any normal arguments.)  See commands/trigger.h for
more information and macros that are commonly used by trigger functions.

* Aggregate functions (or to be precise, their transition and final
functions) are passed an instance of struct AggState, that is the executor
state node for the calling Agg plan node; or if they are called as window
functions, they receive an instance of struct WindowAggState.  It is
recommended that these pointers be used only via AggCheckCallContext()
and sibling functions, which are declared in fmgr.h but are documented
only with their source code in src/backend/executor/nodeAgg.c.  Typically
these context nodes are only of interest when the transition and final
functions wish to optimize execution based on knowing that they are being
used within an aggregate rather than as standalone SQL functions.

* True window functions receive an instance of struct WindowObject.
(Like trigger functions, they don't receive any normal arguments.)
See windowapi.h for more information.

* Procedures are passed an instance of struct CallContext, containing
information about the context of the CALL statement, particularly
whether it is within an "atomic" execution context.

* Some callers of datatype input functions (and in future perhaps
other classes of functions) pass an instance of ErrorSaveContext.
This indicates that the caller wishes to handle "soft" errors without
a transaction-terminating exception being thrown: instead, the callee
should store information about the error cause in the ErrorSaveContext
struct and return a dummy result value.  Further details appear in
"Handling Soft Errors" below.


Handling Soft Errors
--------------------

Postgres' standard mechanism for reporting errors (ereport() or elog())
is used for all sorts of error conditions.  This means that throwing
an exception via ereport(ERROR) requires an expensive transaction or
subtransaction abort and cleanup, since the exception catcher dare not
make many assumptions about what has gone wrong.  There are situations
where we would rather have a lighter-weight mechanism for dealing
with errors that are known to be safe to recover from without a full
transaction cleanup.  SQL-callable functions can support this need
using the ErrorSaveContext context mechanism.

To report a "soft" error, a SQL-callable function should call

	errsave(fcinfo->context, ...)

where it would previously have done

	ereport(ERROR, ...)

If the passed "context" is NULL or is not an ErrorSaveContext node,
then errsave behaves precisely as ereport(ERROR): the exception is
thrown via longjmp, so that control does not return.  If "context"
is an ErrorSaveContext node, then the error information included in
errsave's subsidiary reporting calls is stored into the context node
and control returns from errsave normally.  The function should then
return a dummy value to its caller.  (SQL NULL is recommendable as
the dummy value; but anything will do, since the caller is expected
to ignore the function's return value once it sees that an error has
been reported in the ErrorSaveContext node.)

If there is nothing to do except return after calling errsave(),
you can save a line or two by writing

	ereturn(fcinfo->context, dummy_value, ...)

to perform errsave() and then "return dummy_value".

An error reported "softly" must be safe, in the sense that there is
no question about our ability to continue normal processing of the
transaction.  Error conditions that should NOT be handled this way
include out-of-memory, unexpected internal errors, or anything that
cannot easily be cleaned up after.  Such cases should still be thrown
with ereport, as they have been in the past.

Considering datatype input functions as examples, typical "soft" error
conditions include input syntax errors and out-of-range values.  An
input function typically detects such cases with simple if-tests and
can easily change the ensuing ereport call to an errsave or ereturn.
Because of this restriction, it's typically not necessary to pass
the ErrorSaveContext pointer down very far, as errors reported by
low-level functions are typically reasonable to consider internal.
(Another way to frame the distinction is that input functions should
report all invalid-input conditions softly, but internal problems are
hard errors.)

Because no transaction cleanup will occur, a function that is exiting
after errsave() returns will bear responsibility for resource cleanup.
It is not necessary to be concerned about small leakages of palloc'd
memory, since the caller should be running the function in a short-lived
memory context.  However, resources such as locks, open files, or buffer
pins must be closed out cleanly, as they would be in the non-error code
path.

Conventions for callers that use the ErrorSaveContext mechanism
to trap errors are discussed with the declaration of that struct,
in nodes/miscnodes.h.


Functions Accepting or Returning Sets
-------------------------------------

If a function is marked in pg_proc as returning a set, then it is called
with fcinfo->resultinfo pointing to a node of type ReturnSetInfo.  A
function that desires to return a set should raise an error "called in
context that does not accept a set result" if resultinfo is NULL or does
not point to a ReturnSetInfo node.

There are currently two modes in which a function can return a set result:
value-per-call, or materialize.  In value-per-call mode, the function returns
one value each time it is called, and finally reports "done" when it has no
more values to return.  In materialize mode, the function's output set is
instantiated in a Tuplestore object; all the values are returned in one call.
Additional modes might be added in future.

ReturnSetInfo contains a field "allowedModes" which is set (by the caller)
to a bitmask that's the OR of the modes the caller can support.  The actual
mode used by the function is returned in another field "returnMode".  For
backwards-compatibility reasons, returnMode is initialized to value-per-call
and need only be changed if the function wants to use a different mode.
The function should ereport() if it cannot use any of the modes the caller is
willing to support.

Value-per-call mode works like this: ReturnSetInfo contains a field
"isDone", which should be set to one of these values:

    ExprSingleResult             /* expression does not return a set */
    ExprMultipleResult           /* this result is an element of a set */
    ExprEndResult                /* there are no more elements in the set */

(the caller will initialize it to ExprSingleResult).  If the function simply
returns a Datum without touching ReturnSetInfo, then the call is over and a
single-item set has been returned.  To return a set, the function must set
isDone to ExprMultipleResult for each set element.  After all elements have
been returned, the next call should set isDone to ExprEndResult and return a
null result.  (Note it is possible to return an empty set by doing this on
the first call.)

Value-per-call functions MUST NOT assume that they will be run to completion;
the executor might simply stop calling them, for example because of a LIMIT.
Therefore, it's unsafe to attempt to perform any resource cleanup in the
final call.  It's usually not necessary to clean up memory, anyway.  If it's
necessary to clean up other types of resources, such as file descriptors,
one can register a shutdown callback function in the ExprContext pointed to
by the ReturnSetInfo node.  (But note that file descriptors are a limited
resource, so it's generally unwise to hold those open across calls; SRFs
that need file access are better written to do it in a single call using
Materialize mode.)

Materialize mode works like this: the function creates a Tuplestore holding
the (possibly empty) result set, and returns it.  There are no multiple calls.
The function must also return a TupleDesc that indicates the tuple structure.
The Tuplestore and TupleDesc should be created in the context
econtext->ecxt_per_query_memory (note this will *not* be the context the
function is called in).  The function stores pointers to the Tuplestore and
TupleDesc into ReturnSetInfo, sets returnMode to indicate materialize mode,
and returns null.  isDone is not used and should be left at ExprSingleResult.

The Tuplestore must be created with randomAccess = true if
SFRM_Materialize_Random is set in allowedModes, but it can (and preferably
should) be created with randomAccess = false if not.  Callers that can support
both ValuePerCall and Materialize mode will set SFRM_Materialize_Preferred,
or not, depending on which mode they prefer.

If available, the expected tuple descriptor is passed in ReturnSetInfo;
in other contexts the expectedDesc field will be NULL.  The function need
not pay attention to expectedDesc, but it may be useful in special cases.

InitMaterializedSRF() is a helper function able to setup the function's
ReturnSetInfo for a single call, filling in the Tuplestore and the
TupleDesc with the proper configuration for Materialize mode.

There is no support for functions accepting sets; instead, the function will
be called multiple times, once for each element of the input set.


Notes About Function Handlers
-----------------------------

Handlers for classes of functions should find life much easier and
cleaner in this design.  The OID of the called function is directly
reachable from the passed parameters; we don't need the global variable
fmgr_pl_finfo anymore.  Also, by modifying fcinfo->flinfo->fn_extra,
the handler can cache lookup info to avoid repeat lookups when the same
function is invoked many times.  (fn_extra can only be used as a hint,
since callers are not required to re-use an FmgrInfo struct.
But in performance-critical paths they normally will do so.)

If the handler wants to allocate memory to hold fn_extra data, it should
NOT do so in CurrentMemoryContext, since the current context may well be
much shorter-lived than the context where the FmgrInfo is.  Instead,
allocate the memory in context flinfo->fn_mcxt, or in a long-lived cache
context.  fn_mcxt normally points at the context that was
CurrentMemoryContext at the time the FmgrInfo structure was created;
in any case it is required to be a context at least as long-lived as the
FmgrInfo itself.