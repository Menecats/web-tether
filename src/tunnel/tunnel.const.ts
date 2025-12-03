export const RelayVersion7 = 0x07;
export enum RelayAuthentication {
  BASIC_AUTH = 0x01,
  ADVANCED_AUTH = 0x02,

  UNAUTHORIZED = 0xF0,
  UNSUPPORTED_AUTH = 0xFF,
}
