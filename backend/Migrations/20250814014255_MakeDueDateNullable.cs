using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace backend.Migrations
{
    /// <inheritdoc />
    public partial class MakeDueDateNullable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Tasks",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CreatedAt", "DueDate" },
                values: new object[] { new DateTime(2025, 8, 14, 1, 42, 55, 564, DateTimeKind.Utc).AddTicks(5074), new DateTime(2025, 8, 21, 1, 42, 55, 564, DateTimeKind.Utc).AddTicks(5055) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "Tasks",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CreatedAt", "DueDate" },
                values: new object[] { new DateTime(2025, 8, 14, 1, 42, 41, 19, DateTimeKind.Utc).AddTicks(7685), new DateTime(2025, 8, 21, 1, 42, 41, 19, DateTimeKind.Utc).AddTicks(7668) });
        }
    }
}
