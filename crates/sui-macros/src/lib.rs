// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![no_std]

extern crate alloc;

pub use sui_proc_macros::*;

/// Evaluates an expression in a new thread which will not be subject to interception of
/// getrandom(), clock_gettime(), etc.
#[cfg(msim)]
#[macro_export]
macro_rules! nondeterministic {
    ($expr: expr) => {
        std::thread::scope(move |s| s.spawn(move || $expr).join().unwrap())
    };
}

/// Simply evaluates expr.
#[cfg(not(msim))]
#[macro_export]
macro_rules! nondeterministic {
    ($expr: expr) => {
        $expr
    };
}

#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {
        $crate::handle_fail_point($tag)
    };
}

#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {
        $crate::handle_fail_point_async($tag).await
    };
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {};
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {};
}

// These tests need to be run in release mode, since debug mode does overflow checks by default!
#[cfg(test)]
mod test {
    use super::*;

    // Uncomment to test error messages
    // #[with_checked_arithmetic]
    // struct TestStruct;

    macro_rules! pass_through {
        ($($tt:tt)*) => {
            $($tt)*
        }
    }

    #[with_checked_arithmetic]
    #[test]
    fn test_skip_checked_arithmetic() {
        // comment out this attr to test the error message
        #[skip_checked_arithmetic]
        pass_through! {
            fn unchecked_add(a: i32, b: i32) -> i32 {
                a + b
            }
        }

        // this will not panic even if we pass in (i32::MAX, 1), because we skipped processing
        // the item macro, so we also need to make sure it doesn't panic in debug mode.
        unchecked_add(1, 2);
    }

    checked_arithmetic! {

    struct Test {
        a: i32,
        b: i32,
    }

    fn unchecked_add(a: i32, b: i32) -> i32 {
        a + b
    }

    #[test]
    fn test_checked_arithmetic_macro() {
        unchecked_add(1, 2);
    }

    #[test]
    #[should_panic]
    fn test_checked_arithmetic_macro_panic() {
        unchecked_add(i32::MAX, 1);
    }

    fn unchecked_add_hidden(a: i32, b: i32) -> i32 {
        let inner = |a: i32, b: i32| a + b;
        inner(a, b)
    }

    #[test]
    #[should_panic]
    fn test_checked_arithmetic_macro_panic_hidden() {
        unchecked_add_hidden(i32::MAX, 1);
    }

    fn unchecked_add_hidden_2(a: i32, b: i32) -> i32 {
        fn inner(a: i32, b: i32) -> i32 {
            a + b
        }
        inner(a, b)
    }

    #[test]
    #[should_panic]
    fn test_checked_arithmetic_macro_panic_hidden_2() {
        unchecked_add_hidden_2(i32::MAX, 1);
    }

    impl Test {
        fn add(&self) -> i32 {
            self.a + self.b
        }
    }

    #[test]
    #[should_panic]
    fn test_checked_arithmetic_impl() {
        let t = Test { a: 1, b: i32::MAX };
        t.add();
    }

    #[test]
    #[should_panic]
    fn test_macro_overflow() {
        #[allow(arithmetic_overflow)]
        fn f() {
            println!("{}", i32::MAX + 1);
        }

        f()
    }

    // Make sure that we still do addition correctly!
    #[test]
    fn test_non_overflow() {
        fn f() {
            assert_eq!(1i32 + 2i32, 3i32);
            assert_eq!(3i32 - 1i32, 2i32);
            assert_eq!(4i32 * 3i32, 12i32);
            assert_eq!(12i32 / 3i32, 4i32);
            assert_eq!(12i32 % 5i32, 2i32);

            let mut a = 1i32;
            a += 2i32;
            assert_eq!(a, 3i32);

            let mut a = 3i32;
            a -= 1i32;
            assert_eq!(a, 2i32);

            let mut a = 4i32;
            a *= 3i32;
            assert_eq!(a, 12i32);

            let mut a = 12i32;
            a /= 3i32;
            assert_eq!(a, 4i32);

            let mut a = 12i32;
            a %= 5i32;
            assert_eq!(a, 2i32);
        }

        f();
    }


    #[test]
    fn test_exprs_evaluated_once_right() {
        let mut called = false;
        let mut f = || {
            if called {
                panic!("called twice");
            }
            called = true;
            1i32
        };

        assert_eq!(2i32 + f(), 3);
    }

    #[test]
    fn test_exprs_evaluated_once_left() {
        let mut called = false;
        let mut f = || {
            if called {
                panic!("called twice");
            }
            called = true;
            1i32
        };

        assert_eq!(f() + 2i32, 3);
    }

    #[test]
    fn test_assign_op_evals_once() {
        struct Foo {
            a: i32,
            called: bool,
        }

        impl Foo {
            fn get_a_mut(&mut self) -> &mut i32 {
                if self.called {
                    panic!("called twice");
                }
                let ret = &mut self.a;
                self.called = true;
                ret
            }
        }

        let mut foo = Foo { a: 1, called: false };

        *foo.get_a_mut() += 2;
        assert_eq!(foo.a, 3);
    }

    #[test]
    fn test_more_macro_syntax() {
        struct Foo {
            a: i32,
            b: i32,
        }

        impl Foo {
            const BAR: i32 = 1;

            fn new(a: i32, b: i32) -> Foo {
                Foo { a, b }
            }
        }

        fn new_foo(a: i32) -> Foo {
            Foo { a, b: 0 }
        }

        // verify that we translate the contents of macros correctly
        assert_eq!(Foo::BAR + 1, 2);
        assert_eq!(Foo::new(1, 2).b, 2);
        assert_eq!(new_foo(1).a, 1);

        let v = vec![Foo::new(1, 2), Foo::new(3, 2)];

        assert_eq!(v[0].a, 1);
        assert_eq!(v[1].b, 2);
    }

    }
}
