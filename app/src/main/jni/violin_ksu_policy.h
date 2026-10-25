#pragma once
/* Runtime equivalent of tiann/KernelSU v3.1.0 kernel/selinux/rules.c,
 * apply_kernelsu_rules(). Wildcards below are upstream's root-domain baseline,
 * never an unrestricted allow * * * *. No policy file is persisted/loaded. */
static const char violin_ksu_base_policy[] =
    "permissive su\n"
    "typeattribute su mlstrustedsubject\n"
    "typeattribute su netdomain\n"
    "typeattribute su bluetoothdomain\n"
    "type ksu_file file_type\n"
    "typeattribute ksu_file mlstrustedobject\n"
    "allow * ksu_file * *\n"
    "allow su * * *\n"
    "allowxperm su * blk_file ioctl 0x0000-0xffff\n"
    "allowxperm su * fifo_file ioctl 0x0000-0xffff\n"
    "allowxperm su * chr_file ioctl 0x0000-0xffff\n"
    "allowxperm su * file ioctl 0x0000-0xffff\n"
    "allow init su * *\n"
    "allow servicemanager su dir { search read }\n"
    "allow servicemanager su file { open read }\n"
    "allow servicemanager su process getattr\n"
    "allow * su process sigchld\n"
    "allow logd su dir search\n"
    "allow logd su file { read open getattr }\n"
    "allow * su fd use\n"
    "allow * su fifo_file { write read open getattr }\n"
    "allow hwservicemanager su dir search\n"
    "allow hwservicemanager su file { read open }\n"
    "allow hwservicemanager su process getattr\n"
    "allow * su binder *\n"
    "allow system_server su process { getpgid sigkill }\n";
