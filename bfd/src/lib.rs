// nos-bfd: RFC 5880 BFD core, pure logic only (see bfd/CLAUDE.md): the
// control-packet codec, the session state machine and the timer rules. No
// sockets and no daemon yet; `nos-bfdd` arrives on top of this.

pub mod authz;
pub mod fsm;
pub mod packet;
pub mod timers;
