<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $tableName = config('warden.history.table', 'warden_audit_history');
        
        Schema::create($tableName, function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('audit_type', 50);
            $blueprint->integer('total_findings')->default(0);
            $blueprint->integer('critical_findings')->default(0);
            $blueprint->integer('high_findings')->default(0);
            $blueprint->integer('medium_findings')->default(0);
            $blueprint->integer('low_findings')->default(0);
            $blueprint->json('findings')->nullable();
            $blueprint->json('metadata')->nullable();
            $blueprint->boolean('has_failures')->default(false);
            $blueprint->string('trigger', 50)->default('manual'); // manual, scheduled, api
            $blueprint->string('triggered_by')->nullable();
            $blueprint->integer('duration_ms')->nullable();
            $blueprint->timestamps();
            
            // Indexes for performance
            $blueprint->index('audit_type');
            $blueprint->index('created_at');
            $blueprint->index(['audit_type', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $tableName = config('warden.history.table', 'warden_audit_history');
        Schema::dropIfExists($tableName);
    }
}; 