using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json.Serialization;

namespace UserTemp.Model
{
    public class Common
    {
        [JsonIgnore]
        public bool IsActive { get; set; } = true;
    }

    public class NameAndOrgId
    {
        [BsonElement("Name")]
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
        [Required]
        [JsonPropertyName("organizationId")]
        public string? OrganizationId { get; set; }
    }
    public static class CommonVariables
    {
        public static string ResetPasswordEmailTemplate =
                "<!DOCTYPE html><html lang=\"en-US\"><head> <meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\"/> <title>Reset Password Email Template</title> <meta name=\"description\" content=\"Reset Password Email Template.\"> <style type=\"text/css\"> a:hover{text-decoration: underline !important;}</style> </head><body topmargin=\"0\" style=\"margin: 0px; background-color: #f2f3f8;\" leftmargin=\"0\"> <table border=\"0\" style=\"@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;\"> <tr> <th> <table style=\"background-color: #f2f3f8; max-width:670px; margin:0 auto;\" width=\"100%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\"> <tr> <th style=\"height:80px;\">&nbsp;</th> </tr><tr> <td style=\"text-align:center;\"> <a href=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" target=\"_blank\" rel=noopener> <img width=\"60\" src=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" alt=\"logo\"> </a> </td></tr><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td> <table border=\"0\" style=\"max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);\" summary=\"Table for reset password\"> <tr> <th style=\"height:40px;\">&nbsp;</th> </tr><tr> <td style=\"padding:0 35px;\"> <h1 style=\"color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;\"> You have requested to reset your password </h1> <span style=\"display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;\"></span> <p style=\"color:#455056; font-size:15px;line-height:24px; margin:0;\"> We cannot simply send you your old password. A unique link to reset your password has been generated for you. To reset your password, click the following link and follow the instructions. </p><a href=\"{{APIUrlLink}}\" style=\"background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;\"> Reset Password </a> </td></tr><tr> <td style=\"height:40px;\">&nbsp;</td></tr></table> </td><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td style=\"text-align:center;\"> <p style=\"font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;\">&copy; <strong>www.thinkitive.com</strong></p></td></tr><tr> <td style=\"height:80px;\">&nbsp;</td></tr></table> </th> </tr></table> </body></html>";

        public static string CreatePasswordEmailTemplate =
                "<!DOCTYPE html><html lang=\"en-US\"><head> <meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\"/> <title>Create Password Email Template</title> <meta name=\"description\" content=\"Create Password Email Template.\"> <style type=\"text/css\"> a:hover{text-decoration: underline !important;}</style> </head><body topmargin=\"0\" style=\"margin: 0px; background-color: #f2f3f8;\" leftmargin=\"0\"> <table border=\"0\" style=\"@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;\"> <tr> <th> <table style=\"background-color: #f2f3f8; max-width:670px; margin:0 auto;\" width=\"100%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\"> <tr> <th style=\"height:80px;\">&nbsp;</th> </tr><tr> <td style=\"text-align:center;\"> <a href=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" target=\"_blank\" rel=noopener> <img width=\"60\" src=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" alt=\"logo\"> </a> </td></tr><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td> <table border=\"0\" style=\"max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);\" summary=\"Table for reset password\"> <tr> <th style=\"height:40px;\">&nbsp;</th> </tr><tr> <td style=\"padding:0 35px;\"> <h1 style=\"color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;\"> You have requested to reset your password </h1> <span style=\"display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;\"></span> <p style=\"color:#455056; font-size:15px;line-height:24px; margin:0;\"> We cannot simply send you your old password. A unique link to reset your password has been generated for you. To reset your password, click the following link and follow the instructions. </p><a href=\"{{APIUrlLink}}\" style=\"background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;\"> Create Password </a> </td></tr><tr> <td style=\"height:40px;\">&nbsp;</td></tr></table> </td><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td style=\"text-align:center;\"> <p style=\"font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;\">&copy; <strong>www.thinkitive.com</strong></p></td></tr><tr> <td style=\"height:80px;\">&nbsp;</td></tr></table> </th> </tr></table> </body></html>";

        public static string VerifyEmailTemplate =
                "<!DOCTYPE html><html lang=\"en-US\"><head> <meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\"/> <title>Verify Email Template</title> <meta name=\"description\" content=\"Verify Email Template.\"> <style type=\"text/css\"> a:hover{text-decoration: underline !important;}</style> </head><body topmargin=\"0\" style=\"margin: 0px; background-color: #f2f3f8;\" leftmargin=\"0\"> <table border=\"0\" style=\"@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;\"> <tr> <th> <table style=\"background-color: #f2f3f8; max-width:670px; margin:0 auto;\" width=\"100%\" border=\"0\" align=\"center\" cellpadding=\"0\" cellspacing=\"0\"> <tr> <th style=\"height:80px;\">&nbsp;</th> </tr><tr> <td style=\"text-align:center;\"> <a href=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" target=\"_blank\" rel=noopener> <img width=\"60\" src=\"https://dev-api.resolveengine.com/Content/images/logo.png\" title=\"logo\" alt=\"logo\"> </a> </td></tr><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td> <table border=\"0\" style=\"max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);\" summary=\"Table for reset password\"> <tr> <th style=\"height:40px;\">&nbsp;</th> </tr><tr> <td style=\"padding:0 35px;\"> <h1 style=\"color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;\"> You have requested to reset your password </h1> <span style=\"display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;\"></span> <p style=\"color:#455056; font-size:15px;line-height:24px; margin:0;\"> A unique link to verify your email has been generated for you. To verify your email, click the following link and follow the instructions. </p><a href=\"{{APIUrlLink}}\" style=\"background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;\"> Verify Email</a> </td></tr><tr> <td style=\"height:40px;\">&nbsp;</td></tr></table> </td><tr> <td style=\"height:20px;\">&nbsp;</td></tr><tr> <td style=\"text-align:center;\"> <p style=\"font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;\">&copy; <strong>www.thinkitive.com</strong></p></td></tr><tr> <td style=\"height:80px;\">&nbsp;</td></tr></table> </th> </tr></table> </body></html>";

        public static string ResetPasswordEmailURL = "https://dev-app.resolveengine.com/confirm-password";
        public static string VerifyEmailURL = "https://dev-app.resolveengine.com/verify-email";

    }

    public class DBSetting
    {
        public string ConnectionString { get; set; } = null!;

        public string DatabaseName { get; set; } = null!;
        public string UsersCollectionName { get; set; } = null!;
        public string OrganizationCollectionName { get; set; } = null!;
        public string APIKeysCollectionName { get; set; } = null!;
        public string WebHookCollectionName { get; set; } = null!;
        public string ConnectionCollectionname { get; set; } = null!;
        public string ConfigurationCollectionname { get; set; } = null!;
        public string LogsCollectionname { get; set; } = null!;
        public string ResetPasswordCollectionName { get; set; } = null!;

    }

    public static class Masking
    {
        private static string EncryptDeep(string plainText, string saltText)
        {
            byte[] salt = Encoding.UTF8.GetBytes(saltText);

            var hashed = KeyDerivation.Pbkdf2(
                password: plainText,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8);

            return Convert.ToBase64String(hashed);
        }

        public static string GetEncryptedString(string inputString, string inputSalt)
            => EncryptDeep(inputString, inputSalt);

    }

}

namespace UserTemp.BaseMethod
{
    public class BaseClass<T> where T : class
    {
        public bool IsNotNull()
        {
            if (obj == null) 
                return false;
            return true;
        }
        public bool IsNull()
        {

            return true;
        }
        public bool IsNotNullAndEmpty()
        {
            return true;
        }
        public bool IsNullOrEmpty()
        {
            return true;
        }
    }
}
