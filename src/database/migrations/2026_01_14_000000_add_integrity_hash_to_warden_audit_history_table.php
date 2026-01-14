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

        if (!is_string($tableName)) {
            $tableName = 'warden_audit_history';
        }

        Schema::table($tableName, function (Blueprint $table) {
            $table->string('integrity_hash', 64)->nullable()->after('duration_ms');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $tableName = config('warden.history.table', 'warden_audit_history');

        if (!is_string($tableName)) {
            $tableName = 'warden_audit_history';
        }

        Schema::table($tableName, function (Blueprint $table) {
            $table->dropColumn('integrity_hash');
        });
    }
};
