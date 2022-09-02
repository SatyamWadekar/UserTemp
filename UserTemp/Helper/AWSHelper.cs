using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using System.Net;

namespace UserTemp.Helper
{
    public class AWSHelper
    {
        private readonly string AccessKey;
        
        private readonly string SecretAccessKey;

        private readonly string BucketName;

        private readonly RegionEndpoint Region;

        public AWSHelper(string accessKey, string secretAccessKey, string bucketName, RegionEndpoint region)
        {
            AccessKey = accessKey;
            SecretAccessKey = secretAccessKey;
            BucketName = bucketName;
            Region = region;
        }

        public async Task UploadImage(IFormFile file, string fileName)
        {
            
            using (var client = new AmazonS3Client(AccessKey, SecretAccessKey, Region))
            {
                using (var newMemoryStream = new MemoryStream())
                {
                    file.CopyTo(newMemoryStream);

                    var uploadRequest = new TransferUtilityUploadRequest
                    {
                        InputStream = newMemoryStream,
                        Key = fileName,
                        BucketName = BucketName,
                    };

                    var fileTransferUtility = new TransferUtility(client);
                    await fileTransferUtility.UploadAsync(uploadRequest);
                }
            }
        }

        public string GetImage(string fileName)
        {
            try
            {
                if (!String.IsNullOrWhiteSpace(fileName))
                {
                    using (var client = new AmazonS3Client(AccessKey, SecretAccessKey, Region))
                    {
                        GetPreSignedUrlRequest request = new GetPreSignedUrlRequest
                        {
                            BucketName = BucketName,
                            Key = fileName,
                            Expires = DateTime.Now.AddMinutes(30)
                        };

                        // Get path for request
                        return client.GetPreSignedURL(request);

                    }
                }
                else
                {
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                return "Some error occured while fetching image";
            }

        }

    }
}
