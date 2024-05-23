﻿// <auto-generated />
using H4SoftwareTest.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace H4SoftwareTest.Migrations.Todo
{
    [DbContext(typeof(TodoContext))]
    [Migration("20240407212855_init")]
    partial class init
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.0")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("H4SoftwareTest.Models.Cpr", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"));

                    b.Property<string>("CprNr")
                        .IsRequired()
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<string>("User")
                        .IsRequired()
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.HasKey("Id");

                    b.ToTable("Cpr", (string)null);
                });

            modelBuilder.Entity("H4SoftwareTest.Models.Todolist", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"));

                    b.Property<string>("Item")
                        .IsRequired()
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<int>("UserId")
                        .HasColumnType("int");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("Todolist", (string)null);
                });

            modelBuilder.Entity("H4SoftwareTest.Models.Todolist", b =>
                {
                    b.HasOne("H4SoftwareTest.Models.Cpr", "User")
                        .WithMany("Todolists")
                        .HasForeignKey("UserId")
                        .IsRequired()
                        .HasConstraintName("FK_Todolist_Cpr");

                    b.Navigation("User");
                });

            modelBuilder.Entity("H4SoftwareTest.Models.Cpr", b =>
                {
                    b.Navigation("Todolists");
                });
#pragma warning restore 612, 618
        }
    }
}
