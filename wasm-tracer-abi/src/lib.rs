#![no_std]

pub const MAX_PARAM_COUNT: usize = 5;

#[cfg_attr(feature = "userspace", derive(Debug, Copy, Clone))]
#[repr(C)]
pub struct FunctionMetadata {
    pub param_types: ParamTypes,
    pub param_count: usize,
}

#[cfg(feature = "userspace")]
impl FunctionMetadata {
    pub const fn new(param_types: &[ParamType]) -> Result<Self, ()> {
        let mut param_types_array = [ParamType::Unspecified; MAX_PARAM_COUNT];
        if param_types.len() > MAX_PARAM_COUNT {
            return Err(());
        }

        let mut i = 0;
        while i < param_types.len() {
            param_types_array[i] = param_types[i];
            i += 1;
        }

        Ok(FunctionMetadata {
            param_types: param_types_array,
            param_count: param_types.len(),
        })
    }

    pub const fn new_fixed<const N: usize>(param_types: [ParamType; N]) -> Self {
        assert!(N <= MAX_PARAM_COUNT);

        let Ok(ret) = Self::new(&param_types) else {
            panic!("impossible")
        };

        ret
    }
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FunctionMetadata {}

#[cfg_attr(feature = "userspace", derive(Debug, Copy, Clone))]
#[repr(u8)]
pub enum ParamType {
    Unspecified = 0,
    I8,
    I32,
    I64,
    U8,
    U32,
    U64,
    F32,
    F64,

    /// 1 word for length and 1 word for the pointer to the byte array
    Bytes,
}

pub type ParamTypes = [ParamType; MAX_PARAM_COUNT];

// let first_str_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rcx) });
// let first_str_len = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r8) });
// let second_str_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r9) });
// let stack_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rsp) });
// let second_str_len =
//     unsafe { bpf_probe_read_user((stack_ptr + 8) as *const usize).map_err(|e| e as u32)? };

// let mut entry = FUNCTION_CALLS.reserve_bytes(1024, 0).ok_or(1u32)?;

// let (head, tail) = unsafe { entry.split_at_mut_unchecked(12) };
// head[0..8].copy_from_slice(&read_address(&ctx).to_le_bytes());
// head[8..12]
//     .copy_from_slice(&(4 * 2 + first_str_len as u32 + second_str_len as u32).to_le_bytes());

// let (head, tail) = unsafe { tail.split_at_mut_unchecked(4) };
// head.iter_mut()
//     .zip((first_str_len as u32).to_le_bytes().into_iter())
//     .for_each(|(x, y)| {
//         *x = y;
//     });

// if first_str_len > MAX_DATA_LEN as u64 {
//     return Err(discard(entry, 1));
// }

// let (head, tail) = unsafe { tail.split_at_mut_unchecked(first_str_len as usize) };
// if head
//     .iter_mut()
//     .enumerate()
//     .try_for_each(|(i, x)| {
//         unsafe {
//             *x = bpf_probe_read_user((mem_base + first_str_ptr + i as u64) as *const u8)
//                 .map_err(|x| x as u32)?;
//         }

//         Result::<(), u32>::Ok(())
//     })
//     .is_err()
// {
//     return Err(discard(entry, 1));
// }

// let (head, tail) = unsafe { tail.split_at_mut_unchecked(4) };
// head.iter_mut()
//     .zip((second_str_len as u32).to_le_bytes().into_iter())
//     .for_each(|(x, y)| {
//         *x = y;
//     });

// if second_str_len > MAX_DATA_LEN {
//     return Err(discard(entry, 1));
// }

// let (head, _) = unsafe { tail.split_at_mut_unchecked(second_str_len as usize) };
// if head
//     .iter_mut()
//     .enumerate()
//     .try_for_each(|(i, x)| {
//         unsafe {
//             *x = bpf_probe_read_user((mem_base + second_str_ptr + i as u64) as *const u8)
//                 .map_err(|x| x as u32)?;
//         }

//         Result::<(), u32>::Ok(())
//     })
//     .is_err()
// {
//     return Err(discard(entry, 1));
// }

// entry.submit(0);
