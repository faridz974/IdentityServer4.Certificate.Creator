using CertificateManager;
using CertificateManager.Models;
using CommandLine;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServer4.Certificate.Creator
{
    class Program
    {
        static int Main(string[] args)
        {
            var result = Parser.Default.ParseArguments<Options>(args)
                .MapResult(Run, _ => 1);

            return result;
        }

        private static int Run(Options options)
        {
            try
            {
                var sp = new ServiceCollection()
                    .AddCertificateManager()
                    .BuildServiceProvider();

                var cc = sp.GetService<CreateCertificates>();
                var password = options.Password;
                var iec = sp.GetService<ImportExportCertificate>();
                var filename = $"{options.DnsName}-{options.CertificateType}.pfx";
                if (options.CertificateType == CertificateType.Rsa)
                {
                    var rsaCert = CreateRsaCertificate(cc, options.DnsName, options.ValidityPeriodInYears);
                    var rsaCertPfxBytes = iec.ExportSelfSignedCertificatePfx(password, rsaCert);
                    File.WriteAllBytes(filename, rsaCertPfxBytes);
                }
                else if (options.CertificateType == CertificateType.Ecdsa)
                {
                    var ecdsaCert = CreateEcdsaCertificate(cc, options.DnsName, options.ValidityPeriodInYears);
                    var ecdsaCertPfxBytes =
                        iec.ExportSelfSignedCertificatePfx(password, ecdsaCert);
                    File.WriteAllBytes(filename, ecdsaCertPfxBytes);
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return -1;
            }
        }

        private static X509Certificate2 CreateRsaCertificate(
            CreateCertificates cc,
            string dnsName,
            int validityPeriodInYears)
        {
            var basicConstraints = new BasicConstraints
            {
                CertificateAuthority = false,
                HasPathLengthConstraint = false,
                PathLengthConstraint = 0,
                Critical = false
            };

            var subjectAlternativeName = new SubjectAlternativeName
            {
                DnsName = new List<string> { dnsName }
            };

            var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature;

            // only if certification authentication is used
            var enhancedKeyUsages = new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.1"),  // TLS Server auth
                new Oid("1.3.6.1.5.5.7.3.2"),  // TLS Client auth
            };

            var certificate = cc.NewRsaSelfSignedCertificate(
                new DistinguishedName { CommonName = dnsName },
                basicConstraints,
                new ValidityPeriod
                {
                    ValidFrom = DateTimeOffset.UtcNow,
                    ValidTo = DateTimeOffset.UtcNow.AddYears(validityPeriodInYears)
                },
                subjectAlternativeName,
                enhancedKeyUsages,
                x509KeyUsageFlags,
                new RsaConfiguration { KeySize = 2048 }
            );

            return certificate;
        }

        private static X509Certificate2 CreateEcdsaCertificate(
            CreateCertificates cc,
            string dnsName,
            int validityPeriodInYears)
        {
            var basicConstraints = new BasicConstraints
            {
                CertificateAuthority = false,
                HasPathLengthConstraint = false,
                PathLengthConstraint = 0,
                Critical = false
            };

            var san = new SubjectAlternativeName
            {
                DnsName = new List<string> { dnsName }
            };

            var x509KeyUsageFlags = X509KeyUsageFlags.DigitalSignature;

            // only if certification authentication is used
            var enhancedKeyUsages = new OidCollection {
                new Oid("1.3.6.1.5.5.7.3.1"),  // TLS Server auth
                new Oid("1.3.6.1.5.5.7.3.2"),  // TLS Client auth
            };

            var certificate = cc.NewECDsaSelfSignedCertificate(
                new DistinguishedName { CommonName = dnsName },
                basicConstraints,
                new ValidityPeriod
                {
                    ValidFrom = DateTimeOffset.UtcNow,
                    ValidTo = DateTimeOffset.UtcNow.AddYears(validityPeriodInYears)
                },
                san,
                enhancedKeyUsages,
                x509KeyUsageFlags,
                new ECDsaConfiguration());

            return certificate;
        }
    }

    class Options
    {
        [Option('d', "dns", Required = true, HelpText = "Set dns name of the certificate.")]
        public string DnsName { get; set; } = string.Empty;

        [Option('p', "password", Required = true, HelpText = "Set password of the certificate.")]
        public string Password { get; set; } = string.Empty;

        [Option('v', "validity", Required = false, HelpText = "Set validity period in years of the certificate. By default, it's 10 years.")]
        public int ValidityPeriodInYears { get; set; } = 10;

        [Option('c', "certificate", Required = true, HelpText = "Set the type off the certificate. Possible values: Rsa or Ecdsa")]
        public CertificateType CertificateType { get; set; }
    }

    enum CertificateType
    {
        Rsa,
        Ecdsa
    }
}
