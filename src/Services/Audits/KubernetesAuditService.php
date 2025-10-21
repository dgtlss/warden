<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Illuminate\Support\Facades\Log;
use Exception;

class KubernetesAuditService extends AbstractAuditService
{
    protected array $k8sManifests = [];
    protected array $namespaces = [];
    protected string $kubeconfigPath;

    public function getName(): string
    {
        return 'Kubernetes Security Audit';
    }

    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'kubeconfig_path' => env('KUBECONFIG', '~/.kube/config'),
            'manifest_paths' => [
                'k8s/',
                'kubernetes/',
                'deploy/',
                'manifests/',
                '*.yaml',
                '*.yml',
            ],
            'scan_cluster' => true,
            'scan_manifests' => true,
            'check_rbac' => true,
            'check_network_policies' => true,
            'check_pod_security' => true,
            'check_secrets' => true,
            'check_resource_limits' => true,
            'check_image_security' => true,
            'check_service_accounts' => true,
            'check_admission_controllers' => true,
            'severity_threshold' => 'medium', // low, medium, high, critical
            'timeout' => 300, // 5 minutes for kubectl operations
            'exclude_namespaces' => ['kube-system', 'kube-public', 'kube-node-lease'],
            'exclude_workloads' => [],
        ]);
    }

    protected function onInitialize(): void
    {
        $this->kubeconfigPath = str_replace('~', $_SERVER['HOME'] ?? '~', $this->getConfigValue('kubeconfig_path', '~/.kube/config'));
    }

    protected function onShouldRun(): bool
    {
        // Check if kubectl is available
        if (!$this->isKubectlAvailable()) {
            $this->warning('kubectl is not available');
            return false;
        }

        // Check if cluster is accessible or if we have manifests
        $hasClusterAccess = $this->isClusterAccessible();
        $hasManifests = $this->hasKubernetesManifests();

        if (!$hasClusterAccess && !$hasManifests) {
            $this->info('No Kubernetes cluster access or manifests found, skipping Kubernetes audit');
            return false;
        }

        return true;
    }

    public function run(): bool
    {
        try {
            $this->info('Starting Kubernetes security audit');

            // Scan cluster if enabled and accessible
            if ($this->getConfigValue('scan_cluster', true) && $this->isClusterAccessible()) {
                $this->scanCluster();
            }

            // Scan manifests if enabled and available
            if ($this->getConfigValue('scan_manifests', true) && $this->hasKubernetesManifests()) {
                $this->scanManifests();
            }

            $this->info('Kubernetes security audit completed');
            return empty($this->findings);

        } catch (Exception $e) {
            $this->error('Kubernetes audit failed: ' . $e->getMessage());
            $this->addFinding([
                'package' => 'kubernetes-audit',
                'title' => 'Kubernetes Audit Failed',
                'description' => 'The Kubernetes security audit encountered an error: ' . $e->getMessage(),
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => null,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    protected function scanCluster(): void
    {
        $this->info('Scanning Kubernetes cluster for security issues');

        // Get cluster info
        $this->getClusterInfo();

        // Check RBAC
        if ($this->getConfigValue('check_rbac', true)) {
            $this->checkRBAC();
        }

        // Check Network Policies
        if ($this->getConfigValue('check_network_policies', true)) {
            $this->checkNetworkPolicies();
        }

        // Check Pod Security
        if ($this->getConfigValue('check_pod_security', true)) {
            $this->checkPodSecurity();
        }

        // Check Secrets
        if ($this->getConfigValue('check_secrets', true)) {
            $this->checkClusterSecrets();
        }

        // Check Resource Limits
        if ($this->getConfigValue('check_resource_limits', true)) {
            $this->checkResourceLimits();
        }

        // Check Service Accounts
        if ($this->getConfigValue('check_service_accounts', true)) {
            $this->checkServiceAccounts();
        }

        // Check Admission Controllers
        if ($this->getConfigValue('check_admission_controllers', true)) {
            $this->checkAdmissionControllers();
        }
    }

    protected function scanManifests(): void
    {
        $this->info('Scanning Kubernetes manifests for security issues');

        $this->discoverManifests();

        foreach ($this->k8sManifests as $manifest) {
            $this->scanManifest($manifest);
        }
    }

    protected function getClusterInfo(): void
    {
        try {
            $process = $this->createKubectlProcess(['cluster-info']);
            $process->run();

            if ($process->isSuccessful()) {
                $this->info('Cluster accessible: ' . trim($process->getOutput()));
            } else {
                $this->warning('Cluster info command failed: ' . $process->getErrorOutput());
            }

            // Get namespaces
            $process = $this->createKubectlProcess(['get', 'namespaces', '-o', 'json']);
            $process->run();

            if ($process->isSuccessful()) {
                $data = json_decode($process->getOutput(), true);
                if (isset($data['items'])) {
                    foreach ($data['items'] as $ns) {
                        $this->namespaces[] = $ns['metadata']['name'];
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Failed to get cluster info: ' . $e->getMessage());
        }
    }

    protected function checkRBAC(): void
    {
        $this->info('Checking RBAC configurations');

        try {
            // Check for cluster-admin bindings
            $process = $this->createKubectlProcess(['get', 'clusterrolebindings', '-o', 'json']);
            $process->run();

            if ($process->isSuccessful()) {
                $data = json_decode($process->getOutput(), true);
                if (isset($data['items'])) {
                    foreach ($data['items'] as $binding) {
                        if ($binding['roleRef']['name'] === 'cluster-admin') {
                            foreach ($binding['subjects'] ?? [] as $subject) {
                                if (isset($subject['name']) && $subject['name'] !== 'system:masters') {
                                    $this->addFinding([
                                        'package' => 'kubernetes-rbac',
                                        'title' => 'Cluster Admin Role Binding Detected',
                                        'description' => "User/ServiceAccount '{$subject['name']}' has cluster-admin privileges, which provides full cluster access.",
                                        'severity' => 'high',
                                        'cve' => null,
                                        'affected_versions' => 'all',
                                        'fix_version' => null,
                                        'link' => 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/',
                                    ]);
                                }
                            }
                        }
                    }
                }
            }

            // Check for service accounts with excessive permissions
            $process = $this->createKubectlProcess(['get', 'serviceaccounts', '--all-namespaces', '-o', 'json']);
            $process->run();

            if ($process->isSuccessful()) {
                $data = json_decode($process->getOutput(), true);
                if (isset($data['items'])) {
                    foreach ($data['items'] as $sa) {
                        if ($sa['metadata']['name'] === 'default') {
                            $namespace = $sa['metadata']['namespace'];
                            if (!in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                                $this->addFinding([
                                    'package' => 'kubernetes-rbac',
                                    'title' => 'Default Service Account in Use',
                                    'description' => "Default service account is being used in namespace '{$namespace}'. Consider creating dedicated service accounts.",
                                    'severity' => 'medium',
                                    'cve' => null,
                                    'affected_versions' => 'all',
                                    'fix_version' => null,
                                    'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/',
                                ]);
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('RBAC check failed: ' . $e->getMessage());
        }
    }

    protected function checkNetworkPolicies(): void
    {
        $this->info('Checking Network Policies');

        try {
            foreach ($this->namespaces as $namespace) {
                if (in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                    continue;
                }

                $process = $this->createKubectlProcess(['get', 'networkpolicies', '-n', $namespace, '-o', 'json']);
                $process->run();

                if ($process->isSuccessful()) {
                    $data = json_decode($process->getOutput(), true);
                    $policyCount = isset($data['items']) ? count($data['items']) : 0;

                    if ($policyCount === 0) {
                        $this->addFinding([
                            'package' => 'kubernetes-network-policy',
                            'title' => 'No Network Policies in Namespace',
                            'description' => "Namespace '{$namespace}' has no network policies defined. All pod-to-pod traffic is allowed by default.",
                            'severity' => 'medium',
                            'cve' => null,
                            'affected_versions' => 'all',
                            'fix_version' => null,
                            'link' => 'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
                        ]);
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Network policy check failed: ' . $e->getMessage());
        }
    }

    protected function checkPodSecurity(): void
    {
        $this->info('Checking Pod Security');

        try {
            // Check for pods running as root
            $process = $this->createKubectlProcess(['get', 'pods', '--all-namespaces', '-o', 'json']);
            $process->run();

            if ($process->isSuccessful()) {
                $data = json_decode($process->getOutput(), true);
                if (isset($data['items'])) {
                    foreach ($data['items'] as $pod) {
                        $namespace = $pod['metadata']['namespace'];
                        if (in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                            continue;
                        }

                        $podName = $pod['metadata']['name'];
                        $containers = $pod['spec']['containers'] ?? [];

                        foreach ($containers as $container) {
                            $securityContext = $container['securityContext'] ?? [];
                            
                            // Check for running as root
                            if (isset($securityContext['runAsUser']) && $securityContext['runAsUser'] === 0) {
                                $this->addFinding([
                                    'package' => 'kubernetes-pod-security',
                                    'title' => 'Container Running as Root User',
                                    'description' => "Container '{$container['name']}' in pod '{$podName}' is running as root user.",
                                    'severity' => 'high',
                                    'cve' => null,
                                    'affected_versions' => 'all',
                                    'fix_version' => null,
                                    'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
                                ]);
                            }

                            // Check for privileged containers
                            if (isset($securityContext['privileged']) && $securityContext['privileged']) {
                                $this->addFinding([
                                    'package' => 'kubernetes-pod-security',
                                    'title' => 'Privileged Container Detected',
                                    'description' => "Container '{$container['name']}' in pod '{$podName}' is running in privileged mode.",
                                    'severity' => 'critical',
                                    'cve' => null,
                                    'affected_versions' => 'all',
                                    'fix_version' => null,
                                    'link' => 'https://kubernetes.io/docs/concepts/policy/pod-security-policy/',
                                ]);
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Pod security check failed: ' . $e->getMessage());
        }
    }

    protected function checkClusterSecrets(): void
    {
        $this->info('Checking Cluster Secrets');

        try {
            foreach ($this->namespaces as $namespace) {
                if (in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                    continue;
                }

                $process = $this->createKubectlProcess(['get', 'secrets', '-n', $namespace, '-o', 'json']);
                $process->run();

                if ($process->isSuccessful()) {
                    $data = json_decode($process->getOutput(), true);
                    if (isset($data['items'])) {
                        foreach ($data['items'] as $secret) {
                            $secretName = $secret['metadata']['name'];
                            $secretType = $secret['type'] ?? 'Opaque';

                            // Check for default service account tokens
                            if ($secretType === 'kubernetes.io/service-account-token' && 
                                strpos($secretName, 'default-token-') === 0) {
                                $this->addFinding([
                                    'package' => 'kubernetes-secrets',
                                    'title' => 'Default Service Account Token',
                                    'description' => "Default service account token '{$secretName}' found in namespace '{$namespace}'.",
                                    'severity' => 'medium',
                                    'cve' => null,
                                    'affected_versions' => 'all',
                                    'fix_version' => null,
                                    'link' => 'https://kubernetes.io/docs/concepts/configuration/secret/',
                                ]);
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Secrets check failed: ' . $e->getMessage());
        }
    }

    protected function checkResourceLimits(): void
    {
        $this->info('Checking Resource Limits');

        try {
            foreach ($this->namespaces as $namespace) {
                if (in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                    continue;
                }

                // Check pods without resource limits
                $process = $this->createKubectlProcess(['get', 'pods', '-n', $namespace, '-o', 'json']);
                $process->run();

                if ($process->isSuccessful()) {
                    $data = json_decode($process->getOutput(), true);
                    if (isset($data['items'])) {
                        foreach ($data['items'] as $pod) {
                            $podName = $pod['metadata']['name'];
                            $containers = $pod['spec']['containers'] ?? [];

                            foreach ($containers as $container) {
                                $resources = $container['resources'] ?? [];
                                $limits = $resources['limits'] ?? [];
                                $requests = $resources['requests'] ?? [];

                                if (empty($limits) && empty($requests)) {
                                    $this->addFinding([
                                        'package' => 'kubernetes-resources',
                                        'title' => 'Container Without Resource Limits',
                                        'description' => "Container '{$container['name']}' in pod '{$podName}' has no resource limits or requests defined.",
                                        'severity' => 'medium',
                                        'cve' => null,
                                        'affected_versions' => 'all',
                                        'fix_version' => null,
                                        'link' => 'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/',
                                    ]);
                                }
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Resource limits check failed: ' . $e->getMessage());
        }
    }

    protected function checkServiceAccounts(): void
    {
        $this->info('Checking Service Accounts');

        try {
            foreach ($this->namespaces as $namespace) {
                if (in_array($namespace, $this->getConfigValue('exclude_namespaces', []))) {
                    continue;
                }

                $process = $this->createKubectlProcess(['get', 'serviceaccounts', '-n', $namespace, '-o', 'json']);
                $process->run();

                if ($process->isSuccessful()) {
                    $data = json_decode($process->getOutput(), true);
                    if (isset($data['items'])) {
                        foreach ($data['items'] as $sa) {
                            $saName = $sa['metadata']['name'];
                            $automountToken = $sa['automountServiceAccountToken'] ?? true;

                            if ($saName === 'default' && $automountToken) {
                                $this->addFinding([
                                    'package' => 'kubernetes-service-accounts',
                                    'title' => 'Default Service Account with Auto-mounted Token',
                                    'description' => "Default service account in namespace '{$namespace}' has auto-mounted service account token.",
                                    'severity' => 'medium',
                                    'cve' => null,
                                    'affected_versions' => 'all',
                                    'fix_version' => null,
                                    'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/',
                                ]);
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Service accounts check failed: ' . $e->getMessage());
        }
    }

    protected function checkAdmissionControllers(): void
    {
        $this->info('Checking Admission Controllers');

        try {
            $process = $this->createKubectlProcess(['get', 'pods', '-n', 'kube-system', '-l', 'component=kube-apiserver', '-o', 'json']);
            $process->run();

            if ($process->isSuccessful()) {
                $data = json_decode($process->getOutput(), true);
                if (isset($data['items'])) {
                    foreach ($data['items'] as $pod) {
                        $containers = $pod['spec']['containers'] ?? [];
                        foreach ($containers as $container) {
                            if ($container['name'] === 'kube-apiserver') {
                                $args = $container['args'] ?? [];
                                $admissionControllers = '';

                                foreach ($args as $arg) {
                                    if (strpos($arg, '--enable-admission-plugins=') === 0) {
                                        $admissionControllers = substr($arg, strlen('--enable-admission-plugins='));
                                        break;
                                    }
                                }

                                $requiredControllers = ['PodSecurityPolicy', 'NetworkPolicy', 'ResourceQuota', 'LimitRanger'];
                                $enabledControllers = explode(',', $admissionControllers);

                                foreach ($requiredControllers as $controller) {
                                    if (!in_array($controller, $enabledControllers)) {
                                        $this->addFinding([
                                            'package' => 'kubernetes-admission-controllers',
                                            'title' => 'Missing Admission Controller',
                                            'description' => "Admission controller '{$controller}' is not enabled.",
                                            'severity' => 'medium',
                                            'cve' => null,
                                            'affected_versions' => 'all',
                                            'fix_version' => null,
                                            'link' => 'https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/',
                                        ]);
                                    }
                                }
                            }
                        }
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Admission controllers check failed: ' . $e->getMessage());
        }
    }

    protected function discoverManifests(): void
    {
        $paths = $this->getConfigValue('manifest_paths', []);
        $basePaths = [base_path()];

        foreach ($basePaths as $basePath) {
            foreach ($paths as $path) {
                $fullPath = $basePath . '/' . $path;
                
                if (is_dir($fullPath)) {
                    $this->discoverManifestsInDirectory($fullPath);
                } elseif (file_exists($fullPath)) {
                    $this->k8sManifests[] = $fullPath;
                }
            }
        }
    }

    protected function discoverManifestsInDirectory(string $directory): void
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && in_array($file->getExtension(), ['yaml', 'yml'])) {
                $this->k8sManifests[] = $file->getPathname();
            }
        }
    }

    protected function scanManifest(string $manifestPath): void
    {
        try {
            $content = file_get_contents($manifestPath);
            $documents = $this->parseYamlDocuments($content);

            foreach ($documents as $doc) {
                $this->scanManifestDocument($doc, $manifestPath);
            }

        } catch (Exception $e) {
            $this->warning("Failed to scan manifest {$manifestPath}: " . $e->getMessage());
        }
    }

    protected function parseYamlDocuments(string $content): array
    {
        $documents = [];
        $parts = preg_split('/^---$/m', $content);

        foreach ($parts as $part) {
            $part = trim($part);
            if (!empty($part)) {
                $yaml = yaml_parse($part);
                if ($yaml !== false) {
                    $documents[] = $yaml;
                }
            }
        }

        return $documents;
    }

    protected function scanManifestDocument(array $doc, string $manifestPath): void
    {
        $kind = $doc['kind'] ?? '';
        $metadata = $doc['metadata'] ?? [];
        $name = $metadata['name'] ?? 'unknown';

        switch ($kind) {
            case 'Pod':
            case 'Deployment':
            case 'StatefulSet':
            case 'DaemonSet':
                $this->scanWorkloadManifest($doc, $manifestPath);
                break;
            case 'Service':
                $this->scanServiceManifest($doc, $manifestPath);
                break;
            case 'ConfigMap':
            case 'Secret':
                $this->scanConfigManifest($doc, $manifestPath);
                break;
            case 'NetworkPolicy':
                $this->scanNetworkPolicyManifest($doc, $manifestPath);
                break;
            case 'RBAC':
            case 'Role':
            case 'ClusterRole':
            case 'RoleBinding':
            case 'ClusterRoleBinding':
                $this->scanRBACManifest($doc, $manifestPath);
                break;
        }
    }

    protected function scanWorkloadManifest(array $doc, string $manifestPath): void
    {
        $kind = $doc['kind'];
        $name = $doc['metadata']['name'];
        $spec = $doc['spec'] ?? [];
        $template = $spec['template'] ?? [];
        $podSpec = $template['spec'] ?? $spec;

        // Check security context
        if (isset($podSpec['securityContext'])) {
            $securityContext = $podSpec['securityContext'];
            
            if (isset($securityContext['runAsUser']) && $securityContext['runAsUser'] === 0) {
                $this->addFinding([
                    'package' => 'kubernetes-manifest',
                    'title' => 'Workload Running as Root User',
                    'description' => "{$kind} '{$name}' in {$manifestPath} is configured to run as root user.",
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
                ]);
            }
        }

        // Check containers
        $containers = $podSpec['containers'] ?? [];
        foreach ($containers as $container) {
            $this->scanContainerSecurity($container, $kind, $name, $manifestPath);
        }
    }

    protected function scanContainerSecurity(array $container, string $kind, string $workloadName, string $manifestPath): void
    {
        $containerName = $container['name'];
        $securityContext = $container['securityContext'] ?? [];

        // Check for privileged containers
        if (isset($securityContext['privileged']) && $securityContext['privileged']) {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'Privileged Container in Manifest',
                'description' => "Container '{$containerName}' in {$kind} '{$workloadName}' ({$manifestPath}) is configured as privileged.",
                'severity' => 'critical',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/concepts/policy/pod-security-policy/',
            ]);
        }

        // Check for hostPID or hostIPC
        if (isset($securityContext['hostPID']) && $securityContext['hostPID']) {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'Container with hostPID Access',
                'description' => "Container '{$containerName}' in {$kind} '{$workloadName}' ({$manifestPath}) has access to host PID namespace.",
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
            ]);
        }

        if (isset($securityContext['hostIPC']) && $securityContext['hostIPC']) {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'Container with hostIPC Access',
                'description' => "Container '{$containerName}' in {$kind} '{$workloadName}' ({$manifestPath}) has access to host IPC namespace.",
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/',
            ]);
        }

        // Check image security
        if ($this->getConfigValue('check_image_security', true)) {
            $this->scanContainerImage($container, $kind, $workloadName, $manifestPath);
        }
    }

    protected function scanContainerImage(array $container, string $kind, string $workloadName, string $manifestPath): void
    {
        $image = $container['image'] ?? '';
        $containerName = $container['name'];

        // Check for latest tag
        if (strpos($image, ':latest') !== false || strpos($image, ':') === false) {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'Using Latest Tag in Container Image',
                'description' => "Container '{$containerName}' in {$kind} '{$workloadName}' ({$manifestPath}) uses image '{$image}' with latest tag.",
                'severity' => 'medium',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/concepts/containers/images/',
            ]);
        }

        // Check for insecure registries
        $insecureRegistries = ['docker.io/library', ''];
        foreach ($insecureRegistries as $registry) {
            if (strpos($image, $registry) === 0) {
                $this->addFinding([
                    'package' => 'kubernetes-manifest',
                    'title' => 'Potentially Insecure Image Registry',
                    'description' => "Container '{$containerName}' in {$kind} '{$workloadName}' ({$manifestPath}) uses image from potentially insecure registry.",
                    'severity' => 'low',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/',
                ]);
            }
        }
    }

    protected function scanServiceManifest(array $doc, string $manifestPath): void
    {
        $name = $doc['metadata']['name'];
        $spec = $doc['spec'] ?? [];

        // Check for NodePort services
        if (isset($spec['type']) && $spec['type'] === 'NodePort') {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'NodePort Service Detected',
                'description' => "Service '{$name}' in {$manifestPath} uses NodePort, which exposes services on each node's IP.",
                'severity' => 'medium',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/concepts/services-networking/service/',
            ]);
        }

        // Check for external load balancers without restrictions
        if (isset($spec['type']) && $spec['type'] === 'LoadBalancer') {
            $this->addFinding([
                'package' => 'kubernetes-manifest',
                'title' => 'LoadBalancer Service Detected',
                'description' => "Service '{$name}' in {$manifestPath} uses LoadBalancer, which exposes services externally.",
                'severity' => 'low',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => 'https://kubernetes.io/docs/concepts/services-networking/service/',
            ]);
        }
    }

    protected function scanConfigManifest(array $doc, string $manifestPath): void
    {
        $kind = $doc['kind'];
        $name = $doc['metadata']['name'];
        $data = $doc['data'] ?? [];

        if ($kind === 'Secret') {
            // Check for secrets with weak encoding
            foreach ($data as $key => $value) {
                // Check if the secret value is base64 encoded (it should be)
                $decoded = base64_decode($value, true);
                if ($decoded !== false && is_string($decoded)) {
                    // Check for potential plaintext secrets
                    if (strlen($decoded) < 10) {
                        $this->addFinding([
                            'package' => 'kubernetes-manifest',
                            'title' => 'Potentially Weak Secret',
                            'description' => "Secret '{$name}' in {$manifestPath} contains potentially weak or short secret value for key '{$key}'.",
                            'severity' => 'medium',
                            'cve' => null,
                            'affected_versions' => 'all',
                            'fix_version' => null,
                            'link' => 'https://kubernetes.io/docs/concepts/configuration/secret/',
                        ]);
                    }
                }
            }
        }
    }

    protected function scanNetworkPolicyManifest(array $doc, string $manifestPath): void
    {
        $name = $doc['metadata']['name'];
        $spec = $doc['spec'] ?? [];

        // Check for overly permissive network policies
        if (isset($spec['policyTypes'])) {
            foreach ($spec['policyTypes'] as $policyType) {
                $policySpec = $spec[strtolower($policyType)] ?? [];
                
                if (empty($policySpec)) {
                    $this->addFinding([
                        'package' => 'kubernetes-manifest',
                        'title' => 'Overly Permissive Network Policy',
                        'description' => "NetworkPolicy '{$name}' in {$manifestPath} has empty {$policyType} rules, which may be overly permissive.",
                        'severity' => 'medium',
                        'cve' => null,
                        'affected_versions' => 'all',
                        'fix_version' => null,
                        'link' => 'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
                    ]);
                }
            }
        }
    }

    protected function scanRBACManifest(array $doc, string $manifestPath): void
    {
        $kind = $doc['kind'];
        $name = $doc['metadata']['name'];
        $rules = $doc['rules'] ?? [];

        foreach ($rules as $rule) {
            $verbs = $rule['verbs'] ?? [];
            $resources = $rule['resources'] ?? [];
            $apiGroups = $rule['apiGroups'] ?? [];

            // Check for wildcard permissions
            if (in_array('*', $verbs) && (in_array('*', $resources) || in_array('*', $apiGroups))) {
                $this->addFinding([
                    'package' => 'kubernetes-manifest',
                    'title' => 'Overly Permissive RBAC Rules',
                    'description' => "{$kind} '{$name}' in {$manifestPath} contains overly permissive rules with wildcards.",
                    'severity' => 'high',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/',
                ]);
            }
        }
    }

    protected function isKubectlAvailable(): bool
    {
        try {
            $process = new Process(['kubectl', 'version', '--client']);
            $process->run();
            return $process->isSuccessful();
        } catch (Exception $e) {
            return false;
        }
    }

    protected function isClusterAccessible(): bool
    {
        try {
            $process = $this->createKubectlProcess(['cluster-info']);
            $process->run();
            return $process->isSuccessful();
        } catch (Exception $e) {
            return false;
        }
    }

    protected function hasKubernetesManifests(): bool
    {
        $paths = $this->getConfigValue('manifest_paths', []);
        
        foreach ($paths as $path) {
            $fullPath = base_path($path);
            
            if (is_dir($fullPath)) {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($fullPath, \RecursiveDirectoryIterator::SKIP_DOTS)
                );
                
                foreach ($iterator as $file) {
                    if ($file->isFile() && in_array($file->getExtension(), ['yaml', 'yml'])) {
                        return true;
                    }
                }
            } elseif (file_exists($fullPath)) {
                return true;
            }
        }
        
        return false;
    }

    protected function createKubectlProcess(array $command): Process
    {
        $env = array_merge($_ENV, [
            'KUBECONFIG' => $this->kubeconfigPath,
        ]);

        $process = new Process(array_merge(['kubectl'], $command), null, $env);
        $process->setTimeout($this->getTimeout());
        
        return $process;
    }
}