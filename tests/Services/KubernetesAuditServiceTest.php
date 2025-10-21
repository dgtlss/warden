<?php

namespace Tests\Services;

use PHPUnit\Framework\TestCase;
use Dgtlss\Warden\Services\Audits\KubernetesAuditService;
use Symfony\Component\Process\Process;
use Illuminate\Support\Facades\Log;

class KubernetesAuditServiceTest extends TestCase
{
    protected KubernetesAuditService $auditService;

    protected function setUp(): void
    {
        $this->auditService = new KubernetesAuditService();
        $this->auditService->initialize([
            'enabled' => true,
            'timeout' => 30,
            'scan_cluster' => false, // Disable for testing to avoid kubectl dependency
            'scan_manifests' => true,
            'check_rbac' => true,
            'check_network_policies' => true,
            'check_pod_security' => true,
            'check_secrets' => true,
            'check_resource_limits' => true,
            'check_image_security' => true,
            'manifest_paths' => ['tests/fixtures/k8s'],
        ]);
    }

    public function testGetName()
    {
        $this->assertEquals('Kubernetes Security Audit', $this->auditService->getName());
    }

    public function testDefaultConfig()
    {
        $service = new KubernetesAuditService();
        $config = $service->getConfig();
        
        $this->assertTrue($config['enabled']);
        $this->assertEquals(300, $config['timeout']);
        $this->assertTrue($config['scan_cluster']);
        $this->assertTrue($config['scan_manifests']);
        $this->assertEquals('medium', $config['severity_threshold']);
        $this->assertContains('k8s/', $config['manifest_paths']);
        $this->assertContains('kubernetes/', $config['manifest_paths']);
    }

    public function testShouldRunWithoutKubectlOrManifests()
    {
        $service = $this->createPartialMock(KubernetesAuditService::class, ['isKubectlAvailable', 'hasKubernetesManifests']);
        $service->method('isKubectlAvailable')->willReturn(false);
        $service->method('hasKubernetesManifests')->willReturn(false);
        $service->initialize();
        
        $this->assertFalse($service->shouldRun());
    }

    public function testShouldRunWithKubectl()
    {
        $service = $this->createPartialMock(KubernetesAuditService::class, ['isKubectlAvailable', 'hasKubernetesManifests']);
        $service->method('isKubectlAvailable')->willReturn(true);
        $service->method('hasKubernetesManifests')->willReturn(false);
        $service->initialize();
        
        $this->assertTrue($service->shouldRun());
    }

    public function testShouldRunWithManifests()
    {
        $service = $this->createPartialMock(KubernetesAuditService::class, ['isKubectlAvailable', 'hasKubernetesManifests']);
        $service->method('isKubectlAvailable')->willReturn(false);
        $service->method('hasKubernetesManifests')->willReturn(true);
        $service->initialize();
        
        $this->assertTrue($service->shouldRun());
    }

    public function testParseYamlDocuments()
    {
        $yamlContent = '
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key1: value1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  replicas: 1
';

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('parseYamlDocuments');
        $method->setAccessible(true);

        $documents = $method->invoke($this->auditService, $yamlContent);

        $this->assertCount(2, $documents);
        $this->assertEquals('ConfigMap', $documents[0]['kind']);
        $this->assertEquals('Deployment', $documents[1]['kind']);
    }

    public function testScanWorkloadManifestWithRootUser()
    {
        $manifest = [
            'apiVersion' => 'apps/v1',
            'kind' => 'Deployment',
            'metadata' => ['name' => 'test-deployment'],
            'spec' => [
                'template' => [
                    'spec' => [
                        'securityContext' => [
                            'runAsUser' => 0
                        ],
                        'containers' => [
                            [
                                'name' => 'test-container',
                                'image' => 'nginx:latest'
                            ]
                        ]
                    ]
                ]
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanWorkloadManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $rootUserFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Root User') !== false
        );
        $this->assertNotEmpty($rootUserFindings);
    }

    public function testScanContainerSecurityWithPrivilegedContainer()
    {
        $container = [
            'name' => 'test-container',
            'image' => 'nginx:latest',
            'securityContext' => [
                'privileged' => true
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanContainerSecurity');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $container, 'Deployment', 'test-deployment', 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $privilegedFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Privileged Container') !== false
        );
        $this->assertNotEmpty($privilegedFindings);
        $this->assertEquals('critical', reset($privilegedFindings)['severity']);
    }

    public function testScanContainerSecurityWithHostPID()
    {
        $container = [
            'name' => 'test-container',
            'image' => 'nginx:latest',
            'securityContext' => [
                'hostPID' => true
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanContainerSecurity');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $container, 'Deployment', 'test-deployment', 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $hostPIDFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'hostPID') !== false
        );
        $this->assertNotEmpty($hostPIDFindings);
        $this->assertEquals('high', reset($hostPIDFindings)['severity']);
    }

    public function testScanContainerImageWithLatestTag()
    {
        $container = [
            'name' => 'test-container',
            'image' => 'nginx:latest'
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanContainerImage');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $container, 'Deployment', 'test-deployment', 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $latestTagFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Latest Tag') !== false
        );
        $this->assertNotEmpty($latestTagFindings);
        $this->assertEquals('medium', reset($latestTagFindings)['severity']);
    }

    public function testScanServiceManifestWithNodePort()
    {
        $manifest = [
            'apiVersion' => 'v1',
            'kind' => 'Service',
            'metadata' => ['name' => 'test-service'],
            'spec' => [
                'type' => 'NodePort',
                'selector' => ['app' => 'test'],
                'ports' => [['port' => 80]]
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanServiceManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $nodePortFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'NodePort') !== false
        );
        $this->assertNotEmpty($nodePortFindings);
        $this->assertEquals('medium', reset($nodePortFindings)['severity']);
    }

    public function testScanServiceManifestWithLoadBalancer()
    {
        $manifest = [
            'apiVersion' => 'v1',
            'kind' => 'Service',
            'metadata' => ['name' => 'test-service'],
            'spec' => [
                'type' => 'LoadBalancer',
                'selector' => ['app' => 'test'],
                'ports' => [['port' => 80]]
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanServiceManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $loadBalancerFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'LoadBalancer') !== false
        );
        $this->assertNotEmpty($loadBalancerFindings);
        $this->assertEquals('low', reset($loadBalancerFindings)['severity']);
    }

    public function testScanConfigManifestWithWeakSecret()
    {
        $manifest = [
            'apiVersion' => 'v1',
            'kind' => 'Secret',
            'metadata' => ['name' => 'test-secret'],
            'data' => [
                'password' => base64_encode('weak'), // Short, weak password
                'api-key' => base64_encode('strong-api-key-12345')
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanConfigManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $weakSecretFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Weak Secret') !== false
        );
        $this->assertNotEmpty($weakSecretFindings);
        $this->assertEquals('medium', reset($weakSecretFindings)['severity']);
    }

    public function testScanRBACManifestWithWildcardPermissions()
    {
        $manifest = [
            'apiVersion' => 'rbac.authorization.k8s.io/v1',
            'kind' => 'Role',
            'metadata' => ['name' => 'test-role'],
            'rules' => [
                [
                    'verbs' => ['*'],
                    'resources' => ['*'],
                    'apiGroups' => ['*']
                ]
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanRBACManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $rbacFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'RBAC Rules') !== false
        );
        $this->assertNotEmpty($rbacFindings);
        $this->assertEquals('high', reset($rbacFindings)['severity']);
    }

    public function testScanNetworkPolicyManifestWithEmptyRules()
    {
        $manifest = [
            'apiVersion' => 'networking.k8s.io/v1',
            'kind' => 'NetworkPolicy',
            'metadata' => ['name' => 'test-network-policy'],
            'spec' => [
                'policyTypes' => ['Ingress', 'Egress'],
                'ingress' => [],
                'egress' => []
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanNetworkPolicyManifest');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $manifest, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $networkPolicyFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Network Policy') !== false
        );
        $this->assertNotEmpty($networkPolicyFindings);
        $this->assertEquals('medium', reset($networkPolicyFindings)['severity']);
    }

    public function testIsKubectlAvailable()
    {
        $service = new KubernetesAuditService();
        
        // Use reflection to access protected method
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('isKubectlAvailable');
        $method->setAccessible(true);
        
        // This test will pass if kubectl is installed, fail otherwise
        // In a real test environment, you might want to mock this
        $result = $method->invoke($service);
        $this->assertIsBool($result);
    }

    public function testCreateKubectlProcess()
    {
        $service = new KubernetesAuditService();
        $service->initialize(['kubeconfig_path' => '/test/path/config']);
        
        // Use reflection to access protected method
        $reflection = new \ReflectionClass($service);
        $method = $reflection->getMethod('createKubectlProcess');
        $method->setAccessible(true);
        
        $process = $method->invoke($service, ['version', '--client']);
        
        $this->assertInstanceOf(Process::class, $process);
        $command = $process->getCommandLine();
        $this->assertStringContains('kubectl', $command);
        $this->assertStringContains('version', $command);
        $this->assertStringContains('--client', $command);
    }

    public function testScanManifestDocument()
    {
        $document = [
            'apiVersion' => 'apps/v1',
            'kind' => 'Deployment',
            'metadata' => ['name' => 'test-deployment'],
            'spec' => [
                'template' => [
                    'spec' => [
                        'containers' => [
                            [
                                'name' => 'test-container',
                                'image' => 'nginx:latest',
                                'securityContext' => [
                                    'privileged' => true
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];

        // Use reflection to access protected method
        $reflection = new \ReflectionClass($this->auditService);
        $method = $reflection->getMethod('scanManifestDocument');
        $method->setAccessible(true);

        $method->invoke($this->auditService, $document, 'test.yaml');
        $findings = $this->auditService->getFindings();

        $this->assertNotEmpty($findings);
        $privilegedFindings = array_filter($findings, fn($f) => 
            strpos($f['title'], 'Privileged Container') !== false
        );
        $this->assertNotEmpty($privilegedFindings);
    }

    public function testRunWithManifestsOnly()
    {
        // Create a temporary manifest file
        $tempDir = sys_get_temp_dir() . '/k8s_test_' . uniqid();
        mkdir($tempDir, 0755, true);
        
        $manifestContent = '
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  template:
    spec:
      containers:
        - name: test-container
          image: nginx:latest
          securityContext:
            privileged: true
';

        $manifestFile = $tempDir . '/deployment.yaml';
        file_put_contents($manifestFile, $manifestContent);

        // Mock base_path function
        if (!function_exists('base_path')) {
            function base_path($path) {
                global $tempDir;
                return $path === 'tests/fixtures/k8s' ? $tempDir : '/tmp';
            }
        }

        $service = new KubernetesAuditService();
        $service->initialize([
            'scan_cluster' => false,
            'scan_manifests' => true,
            'manifest_paths' => ['tests/fixtures/k8s']
        ]);

        $result = $service->run();
        $findings = $service->getFindings();

        $this->assertFalse($result); // Should return false due to findings
        $this->assertNotEmpty($findings);

        // Cleanup
        unlink($manifestFile);
        rmdir($tempDir);
    }
}