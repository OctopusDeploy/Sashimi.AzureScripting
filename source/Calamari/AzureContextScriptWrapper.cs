using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Calamari.Common.Features.Discovery;
using Calamari.Common.Features.EmbeddedResources;
using Calamari.Common.Features.Processes;
using Calamari.Common.Features.Scripting;
using Calamari.Common.Features.Scripts;
using Calamari.Common.Plumbing.FileSystem;
using Calamari.Common.Plumbing.Logging;
using Calamari.Common.Plumbing.Variables;
using Newtonsoft.Json;

namespace Calamari.AzureScripting
{
    public class AzureContextScriptWrapper : IScriptWrapper
    {
        const string CertificateFileName = "azure_certificate.pfx";
        const int PasswordSizeBytes = 20;
        const string DefaultAzureEnvironment = "AzureCloud";

        readonly ICalamariFileSystem fileSystem;
        readonly ICalamariEmbeddedResources embeddedResources;
        readonly ILog log;
        readonly IVariables variables;
        readonly ScriptSyntax[] supportedScriptSyntax = {ScriptSyntax.PowerShell, ScriptSyntax.Bash};

        public AzureContextScriptWrapper(IVariables variables, ICalamariFileSystem fileSystem, ICalamariEmbeddedResources embeddedResources, ILog log)
        {
            this.variables = variables;
            this.fileSystem = fileSystem;
            this.embeddedResources = embeddedResources;
            this.log = log;
        }

        public int Priority => ScriptWrapperPriorities.CloudAuthenticationPriority;

        public bool IsEnabled(ScriptSyntax syntax) => supportedScriptSyntax.Contains(syntax);

        public IScriptWrapper? NextWrapper { get; set; }

        public CommandResult ExecuteScript(Script script,
                                           ScriptSyntax scriptSyntax,
                                           ICommandLineRunner commandLineRunner,
                                           Dictionary<string, string>? environmentVars)
        {
            var workingDirectory = Path.GetDirectoryName(script.File)!;
            variables.Set("OctopusAzureTargetScript", script.File);
            variables.Set("OctopusAzureTargetScriptParameters", script.Parameters);

            var cloudConnectionContext = GetCloudConnectionContext(variables);
            AzureContextScriptWrapperAuthentication? scriptAuthentication;
            if (cloudConnectionContext != null)
            {
                scriptAuthentication = AzureContextScriptWrapperAuthentication.CreateFromCloudConnectionContext(cloudConnectionContext);
            }
            else
            {
                scriptAuthentication = AzureContextScriptWrapperAuthentication.CreateFromKnownVariables(variables);
            }

            SetOutputVariable("OctopusAzureSubscriptionId", scriptAuthentication.SubscriptionId);
            SetOutputVariable("OctopusAzureStorageAccountName", scriptAuthentication.StorageAccountName!);
            if (scriptAuthentication.AzureEnvironment != DefaultAzureEnvironment)
            {
                log.InfoFormat("Using Azure Environment override - {0}", scriptAuthentication.AzureEnvironment!);
            }
            SetOutputVariable("OctopusAzureEnvironment", scriptAuthentication.AzureEnvironment!);
            SetOutputVariable("OctopusAzureExtensionsDirectory", variables.Get(SpecialVariables.Action.Azure.ExtensionsDirectory)!);

            using (new TemporaryFile(Path.Combine(workingDirectory, "AzureProfile.json")))
            using (var contextScriptFile = new TemporaryFile(CreateContextScriptFile(workingDirectory, scriptSyntax)))
            {
                if (scriptAuthentication.UseServicePrincipal)
                {
                    SetOutputVariable("OctopusUseServicePrincipal", bool.TrueString);
                    SetOutputVariable("OctopusAzureADTenantId", scriptAuthentication.TenantId!);
                    SetOutputVariable("OctopusAzureADClientId", scriptAuthentication.ClientId!);
                    variables.Set("OctopusAzureADPassword", scriptAuthentication.Password);
                    return NextWrapper!.ExecuteScript(new Script(contextScriptFile.FilePath), scriptSyntax, commandLineRunner, environmentVars);
                }

                //otherwise use management certificate
                SetOutputVariable("OctopusUseServicePrincipal", false.ToString());
                using (new TemporaryFile(CreateAzureCertificate(workingDirectory, scriptAuthentication)))
                {
                    return NextWrapper!.ExecuteScript(new Script(contextScriptFile.FilePath), scriptSyntax, commandLineRunner, environmentVars);
                }
            }
        }

        private class CloudConnectionContext<TAuthentication>
        {
            public TAuthentication Authentication { get; set; }

            public CloudConnectionContext(TAuthentication authentication)
            {
                Authentication = authentication;
            }
        }

        private class AzureCloudConnectionAuthentication
        {
            public ServicePrincipalAccount AccountDetails { get; set; }

            public AzureCloudConnectionAuthentication(ServicePrincipalAccount accountDetails)
            {
                AccountDetails = accountDetails;
            }
        }

        class AzureContextScriptWrapperAuthentication
        {
            public AzureContextScriptWrapperAuthentication(
                string subscriptionId,
                string azureEnvironment,
                string? clientId,
                string? tenantId,
                string? password,
                string? storageAccountName,
                string? certificateThumbprint,
                byte[]? certificateBytes,
                bool useServicePrincipal)
            {
                SubscriptionId = subscriptionId;
                AzureEnvironment = azureEnvironment;
                ClientId = clientId;
                TenantId = tenantId;
                Password = password;
                StorageAccountName = storageAccountName;
                CertificateThumbprint = certificateThumbprint;
                CertificateBytes = certificateBytes;
                UseServicePrincipal = useServicePrincipal;
            }

            public static AzureContextScriptWrapperAuthentication CreateFromKnownVariables(IVariables variables)
            {
                return new AzureContextScriptWrapperAuthentication(
                    subscriptionId: variables.Get(SpecialVariables.Action.Azure.SubscriptionId)!,
                    azureEnvironment: variables.Get(SpecialVariables.Action.Azure.Environment, DefaultAzureEnvironment)!,
                    clientId: variables.Get(SpecialVariables.Action.Azure.ClientId),
                    tenantId: variables.Get(SpecialVariables.Action.Azure.TenantId),
                    password: variables.Get(SpecialVariables.Action.Azure.Password),
                    variables.Get(SpecialVariables.Action.Azure.StorageAccountName)!,
                    variables.Get(SpecialVariables.Action.Azure.CertificateThumbprint),
                    variables.IsSet(SpecialVariables.Action.Azure.CertificateBytes) ? Convert.FromBase64String(variables.Get(SpecialVariables.Action.Azure.CertificateBytes)!) : null,
                    variables.Get(SpecialVariables.Account.AccountType) == "AzureServicePrincipal");
            }

            public static AzureContextScriptWrapperAuthentication CreateFromCloudConnectionContext(CloudConnectionContext<AzureCloudConnectionAuthentication> context)
            {
                return new AzureContextScriptWrapperAuthentication(
                    context.Authentication.AccountDetails.SubscriptionNumber,
                    context.Authentication.AccountDetails.AzureEnvironment ?? DefaultAzureEnvironment,
                    context.Authentication.AccountDetails.ClientId,
                    context.Authentication.AccountDetails.TenantId,
                    context.Authentication.AccountDetails.Password,
                    null,
                    null, 
                    null,
                    true);
            }

            public string SubscriptionId { get; }
            public string AzureEnvironment { get; }
            public string? ClientId { get; }
            public string? TenantId { get; }
            public string? Password { get; }
            public string? StorageAccountName { get; set; }
            public string? CertificateThumbprint { get; set; }
            public byte[]? CertificateBytes { get; set; }
            public bool UseServicePrincipal { get; set; }
        }

        class ServicePrincipalAccount
        {
            public ServicePrincipalAccount(
                string subscriptionNumber,
                string clientId,
                string tenantId,
                string password,
                string? azureEnvironment)
            {
                SubscriptionNumber = subscriptionNumber;
                ClientId = clientId;
                TenantId = tenantId;
                Password = password;
                AzureEnvironment = azureEnvironment;
            }

            public string SubscriptionNumber { get; }
            public string ClientId { get; }
            public string TenantId { get; }
            public string Password { get; }
            public string? AzureEnvironment { get; }
        }

        private CloudConnectionContext<AzureCloudConnectionAuthentication>? GetCloudConnectionContext(IVariables variables)
        {
            const string contextVariableName = "Octopus.CloudConnection.Context";
            var json = variables.Get(contextVariableName);
            if (json == null)
            {
                return null;
            }

            try
            {
                return JsonConvert.DeserializeObject<CloudConnectionContext<AzureCloudConnectionAuthentication>>(json);
            }
            catch (Exception ex)
            {
                Log.Warn($"Cloud connection context from variable {contextVariableName} is in wrong format: {ex.Message}");
                return null;
            }
        }

        string CreateContextScriptFile(string workingDirectory, ScriptSyntax syntax)
        {
            string contextFile;
            switch (syntax)
            {
                case ScriptSyntax.Bash:
                    contextFile = "AzureContext.sh";
                    break;
                case ScriptSyntax.PowerShell:
                    contextFile = "AzureContext.ps1";
                    break;
                default:
                    throw new InvalidOperationException($"No Azure context wrapper exists for {syntax}");
            }

            var azureContextScriptFile = Path.Combine(workingDirectory, $"Octopus.{contextFile}");
            var contextScript = embeddedResources.GetEmbeddedResourceText(GetType().Assembly, $"{GetType().Namespace}.Scripts.{contextFile}");
            fileSystem.OverwriteFile(azureContextScriptFile, contextScript);
            return azureContextScriptFile;
        }

        string CreateAzureCertificate(string workingDirectory, AzureContextScriptWrapperAuthentication scriptAuthentication)
        {
            var certificateFilePath = Path.Combine(workingDirectory, CertificateFileName);
            var certificatePassword = GenerateCertificatePassword();
            var azureCertificate = CalamariCertificateStore.GetOrAdd(scriptAuthentication.CertificateThumbprint!,
                                                                     scriptAuthentication.CertificateBytes!,
                                                                     StoreName.My);

            variables.Set("OctopusAzureCertificateFileName", certificateFilePath);
            variables.Set("OctopusAzureCertificatePassword", certificatePassword);

            fileSystem.WriteAllBytes(certificateFilePath, azureCertificate.Export(X509ContentType.Pfx, certificatePassword));
            return certificateFilePath;
        }

        void SetOutputVariable(string name, string value)
        {
            if (variables.Get(name) != value)
            {
                log.SetOutputVariable(name, value, variables);
            }
        }

        static string GenerateCertificatePassword()
        {
            var random = RandomNumberGenerator.Create();
            var bytes = new byte[PasswordSizeBytes];
            random.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}