#include "ScreenRunnerBSD.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void check(int value, const char *name) { if (!value) { fprintf(stderr,"ASSERTION:%s\n",name); exit(1); } }
static struct sliccy_runner_bsd_read reading(int pid, int parent, unsigned int uid) {
    return (struct sliccy_runner_bsd_read){0,136,136,{pid,parent,uid,uid,uid,123,456}};
}
static struct sliccy_runner_bsd_observation fixture(void) {
    struct sliccy_runner_bsd_observation o = {.self_pid=10,.parent_pid=11};
    o.controls[0].before=o.controls[0].proc=o.controls[0].after=reading(10,11,501);
    o.controls[1].before=o.controls[1].proc=o.controls[1].after=reading(11,1,501);
    o.target.before=o.target.proc=o.target.after=reading(42,1,88);
    o.target.before.value.real_uid=o.target.proc.value.real_uid=o.target.after.value.real_uid=0;
    o.target.before.value.saved_uid=o.target.proc.value.saved_uid=o.target.after.value.saved_uid=0;
    return o;
}
static int select_identity(struct sliccy_runner_bsd_observation o) {
    struct sliccy_runner_bsd_value v={0}; int used=-1;
    return sliccy_bsd_select(o,42,&v,&used);
}
static struct sliccy_runner_bsd_observation denied(void) {
    struct sliccy_runner_bsd_observation o=fixture();
    o.target.proc=(struct sliccy_runner_bsd_read){.status=EPERM,.expected=136};return o;
}
int main(int argc, char **argv) {
    if (argc!=2) return 2;
    struct sliccy_runner_bsd_observation o=denied();
    struct sliccy_runner_bsd_value a=o.target.before.value,b=a; int used=-1;
    check(sliccy_bsd_select(o,42,&a,&used)==0 && used==1,"baseline-fallback");
    check(select_identity(fixture())==0,"baseline-proc");
    check(sliccy_bsd_windowserver(a,b),"baseline-windowserver");
    if (!strcmp(argv[1],"controls")) { o.controls[0].proc.value.real_uid++; check(select_identity(o)!=0,"controls"); }
    else if (!strcmp(argv[1],"control-after")) { o.controls[1].after.value.saved_uid++; check(select_identity(o)!=0,"control-after"); }
    else if (!strcmp(argv[1],"unstable")) { o.target.after.value.microseconds++; check(select_identity(o)!=0,"unstable"); }
    else if (!strcmp(argv[1],"eperm-only")) { o.target.proc.status=ESRCH; check(select_identity(o)!=0,"eperm-only"); }
    else if (!strcmp(argv[1],"short")) { o.target.before.count--; check(select_identity(o)!=0,"short"); }
    else if (!strcmp(argv[1],"effective")) { a.effective_uid=b.effective_uid=89; check(!sliccy_bsd_windowserver(a,b),"effective"); }
    else if (!strcmp(argv[1],"real")) { a.real_uid=b.real_uid=1; check(!sliccy_bsd_windowserver(a,b),"real"); }
    else if (!strcmp(argv[1],"saved")) { a.saved_uid=b.saved_uid=1; check(!sliccy_bsd_windowserver(a,b),"saved"); }
    else if (!strcmp(argv[1],"binding")) { b.seconds++; check(!sliccy_bsd_windowserver(a,b),"binding"); }
    else if (!strcmp(argv[1],"parent")) { a.parent=b.parent=2; check(!sliccy_bsd_windowserver(a,b),"parent"); }
    else if (!strcmp(argv[1],"fields")) {
        for (int field=0;field<7;field++) {
            struct sliccy_runner_bsd_observation c=denied();
            struct sliccy_runner_bsd_value *v=&c.controls[1].proc.value;
            switch(field) {case 0:v->pid++;break;case 1:v->parent++;break;case 2:v->effective_uid++;break;case 3:v->real_uid++;break;case 4:v->saved_uid++;break;case 5:v->seconds++;break;default:v->microseconds++;}
            check(select_identity(c)!=0,"fields");
        }
        o.controls[0].proc.status=EPERM;check(select_identity(o)!=0,"missing-control");
        o=denied();o.parent_pid=o.self_pid;check(select_identity(o)!=0,"distinct-controls");
        o=fixture();o.target.proc.value.saved_uid++;check(select_identity(o)!=0,"readable-disagreement");
        o=denied();o.target.before.value.pid=43;check(select_identity(o)!=0,"wrong-pid");
        o=denied();o.target.before.value.seconds=0;check(select_identity(o)!=0,"zero-start");
    } else return 2;
    return 0;
}
