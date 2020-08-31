LaancTokenHelper

Work Completed:
- Validate JWT against JWK from local cache, based on KID.
- Retrieve JWK from FAA server and save it to local cache
- Using Native JsonWebKeyset to store cached keys
- Complete API integration with sample response using MockAPI.IO
- Fully tested with NUnitTest
- Performance is tested: (new JWK retrial depends on server response time ~100ms, validating JWT against cached keys is instant, iteration i = 1000, t < 1s)

Work needed:- LaancTokenHandler.cs : 21 - FAAbaseUrl (Need to point to FAA URL, currently it points to mockapi.io with sample response)
- LaancTokenHandler.cs : 42 - validationParameters (need to custom validation requirement, ie. Expiration Validation, Aud, Iss)
- LaancTokenHandler.cs : 128 - faaLaancJWK (might need to modify the Json Deserializer according to exact FAA response)

Usage:
Refer to Program.cs or Test Cases

Resources:
Sample API : https://5f4c10d1ea007b0016b1dd4f.mockapi.io/oauth/v4/key/?kid=1e9gdk7
Source Code: https://github.com/suchiham/LaancTokenHelper


