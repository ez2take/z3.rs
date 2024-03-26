use std::ffi::{CStr, CString};
use std::fmt;
use std::rc::Rc;
use std::result::Result;
use std::str::Utf8Error;

use z3_sys::*;

use crate::{Context, Goal, Probe};

impl Probe {
    unsafe fn wrap(ctx: Rc<Context>, z3_probe: Z3_probe) -> Probe {
        Z3_probe_inc_ref(ctx.z3_ctx, z3_probe);
        Probe { ctx, z3_probe }
    }

    /// Iterate through the valid probe names.
    ///
    /// # Example
    ///
    /// ```
    /// use z3::{Config, Context, Probe};
    ///
    /// let cfg = Config::new();
    /// let ctx = Context::new(&cfg);
    /// let probes: Vec<_> = Probe::list_all(&ctx).filter_map(|r| r.ok()).collect();
    /// assert!(probes.contains(&"is-quasi-pb"));
    /// ```
    pub fn list_all<'a>(
        ctx: &'a Context,
    ) -> impl Iterator<Item = std::result::Result<&'a str, Utf8Error>> {
        let p = unsafe { Z3_get_num_probes(ctx.z3_ctx) };
        (0..p).map(move |n| {
            let t = unsafe { Z3_get_probe_name(ctx.z3_ctx, n) };
            unsafe { CStr::from_ptr(t) }.to_str()
        })
    }

    /// Return a string containing a description of the probe with
    /// the given `name`.
    pub fn describe(ctx: Rc<Context>, name: &str) -> std::result::Result<&str, Utf8Error> {
        let probe_name = CString::new(name).unwrap();
        unsafe { CStr::from_ptr(Z3_probe_get_descr(ctx.z3_ctx, probe_name.as_ptr())).to_str() }
    }

    /// Return a probe associated with the given `name`.
    ///
    /// # Example
    ///
    /// ```
    /// use z3::{Config, Context, Probe};
    ///
    /// let cfg = Config::new();
    /// let ctx = Context::new(&cfg);
    /// let probe = Probe::new(&ctx, "is-qfbv");
    /// ```
    pub fn new(ctx: Rc<Context>, name: &str) -> Probe {
        let probe_name = CString::new(name).unwrap();
        unsafe {
            let probe = Z3_mk_probe(ctx.z3_ctx, probe_name.as_ptr());
            Self::wrap(ctx, probe)
        }
    }

    /// Execute the probe over the goal.
    ///
    /// The probe always produce a double value. "Boolean" probes return
    /// `0.0` for `false`, and a value different from `0.0` for `true`.
    pub fn apply(&self, goal: &Goal) -> f64 {
        unsafe { Z3_probe_apply(self.ctx.z3_ctx, self.z3_probe, goal.z3_goal) }
    }

    /// Return a probe that always evaluates to val.
    /// ```
    /// use z3::{Config, Context, Probe};
    ///
    /// let cfg = Config::new();
    /// let ctx = Context::new(&cfg);
    /// let probe = Probe::constant(&ctx, 1.0);
    /// ```
    pub fn constant(ctx: Rc<Context>, val: f64) -> Probe {
        unsafe {
            let probe = Z3_probe_const(ctx.z3_ctx, val);
            Self::wrap(ctx, probe)
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is less than the value returned by `p`.
    ///
    /// NOTE: For probes, "true" is any value different from 0.0.
    pub fn lt(&self, p: Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_lt(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is greater than the value returned by `p`.
    pub fn gt(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_gt(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is less than or equal to the value returned by `p`.
    pub fn le(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_le(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is greater than or equal to the value returned by `p`.
    pub fn ge(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_ge(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is equal to the value returned by `p`.
    pub fn eq(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_eq(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when `self` and `p` evaluates to true.
    pub fn and(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_and(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when `p1` or `p2` evaluates to true.
    pub fn or(&self, p: &Probe) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_or(self.ctx.z3_ctx, self.z3_probe, p.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when `p` does not evaluate to true.
    pub fn not(&self) -> Probe {
        unsafe {
            Self::wrap(
                self.ctx.clone(),
                Z3_probe_not(self.ctx.z3_ctx, self.z3_probe),
            )
        }
    }

    /// Return a probe that evaluates to "true" when the value returned
    /// by `self` is not equal to the value returned by `p`.
    pub fn ne(&self, p: &Probe) -> Probe {
        self.eq(p).not()
    }
}

impl Clone for Probe {
    fn clone(&self) -> Self {
        unsafe { Self::wrap(self.ctx.clone(), self.z3_probe) }
    }
}

impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "<z3.probe>")
    }
}

impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        unsafe {
            Z3_probe_dec_ref(self.ctx.z3_ctx, self.z3_probe);
        }
    }
}
