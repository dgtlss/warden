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
        
        Schema::create($tableName, function (Blueprint $table) {
            $table->id();
            $table->string('audit_type', 50);
            $table->integer('total_findings')->default(0);
            $table->integer('critical_findings')->default(0);
            $table->integer('high_findings')->default(0);
            $table->integer('medium_findings')->default(0);
            $table->integer('low_findings')->default(0);
            $table->json('findings')->nullable();
            $table->json('metadata')->nullable();
            $table->boolean('has_failures')->default(false);
            $table->string('trigger', 50)->default('manual'); // manual, scheduled, api
            $table->string('triggered_by')->nullable();
            $table->integer('duration_ms')->nullable();
            $table->timestamps();
            
            // Indexes for performance
            $table->index('audit_type');
            $table->index('created_at');
            $table->index(['audit_type', 'created_at']);
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