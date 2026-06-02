use std::{any::type_name, fmt, slice::SliceIndex};

pub trait TryAdd: Sized {
    /// Attempts to add `self + rhs`, returning `Err` if overflow occurred.
    fn try_add(self, rhs: Self) -> Result<Self, String>;
}

/// Generates `TryAdd` implementations for all types passed as comma-separated arguments. Limited to
/// primitive integer types.
macro_rules! impl_try_add {
    ($($t:ty),+ $(,)?) => {
        $(
            impl TryAdd for $t {
                fn try_add(self, rhs: Self) -> Result<Self, String> {
                    self.checked_add(rhs).ok_or_else(|| {
                        format!("Overflowed `{}` adding {self} and {rhs}", stringify!($t))
                    })
                }
            }
        )+
    };
}

impl_try_add!(usize, u16);

pub trait TryGet {
    /// Returns a reference to the element or subslice at `index`, or `Err` if out of bounds.
    fn try_get<I>(&self, index: I) -> Result<&I::Output, String>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone;
}

impl<T> TryGet for [T] {
    fn try_get<I>(&self, index: I) -> Result<&I::Output, String>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone,
    {
        let n = self.len();

        self.get(index.clone()).ok_or_else(|| {
            format!(
                "Index {index:?} out of range on `[{}]` of length {n}",
                type_name::<T>()
            )
        })
    }
}

pub trait TryGetMut {
    /// Returns a mutable reference to the element or subslice at `index`, or `Err` if out of
    /// bounds.
    fn try_get_mut<I>(&mut self, index: I) -> Result<&mut I::Output, String>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone;
}

impl<T> TryGetMut for [T] {
    fn try_get_mut<I>(&mut self, index: I) -> Result<&mut I::Output, String>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone,
    {
        let n = self.len();

        self.get_mut(index.clone()).ok_or_else(|| {
            format!(
                "Index {index:?} out of range on `[{}]` of length {n}",
                type_name::<T>()
            )
        })
    }
}
