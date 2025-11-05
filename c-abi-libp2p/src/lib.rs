pub fn add(left: u64, right: u64) -> u64 {
    left + right
}
pub mod config;
pub mod messaging;
pub mod peer;
pub mod transport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
pub use messaging::*;
pub use peer::*;
pub use transport::*;