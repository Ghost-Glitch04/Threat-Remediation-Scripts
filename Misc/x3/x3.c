#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libgen.h>
#include <ftw.h>
#include <signal.h>
#include <fnmatch.h>
#include <ctype.h>
#include <dirent.h>
#include <termios.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>

#define TMP_TEMPLATE "/tmp/x3-XXXXXX"
#define BUF_SIZE 8192
#define MAX_RESULTS 2048

static char g_tmpdir[sizeof(TMP_TEMPLATE)];
static int g_tmpdir_created = 0;
static char *g_root = NULL;
static pid_t g_child_pid = -1;

static struct termios orig_term;
static int term_raw = 0;

static char *results[MAX_RESULTS];
static int result_count = 0;
static int selected = 0;
static char *current_dir = NULL;

static void reset_results(void);
static void restore_terminal(void);

static int unlink_cb(const char *fpath, const struct stat *sb, int t, struct FTW *ftw)
{
    (void)sb;
    (void)t;
    (void)ftw;
    return remove(fpath);
}

static void cleanup(void)
{
    if (term_raw) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);
        term_raw = 0;
    }

    if (g_child_pid > 0) {
        killpg(g_child_pid, SIGTERM);
        usleep(200000);
        int status;
        if (waitpid(g_child_pid, &status, WNOHANG) == 0) {
            killpg(g_child_pid, SIGKILL);
            waitpid(g_child_pid, NULL, 0);
        }
        g_child_pid = -1;
    }

    if (g_tmpdir_created) {
        nftw(g_tmpdir, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
        g_tmpdir_created = 0;
    }

    reset_results();
    if (current_dir) {
        free(current_dir);
        current_dir = NULL;
    }
    if (g_root) {
        free(g_root);
        g_root = NULL;
    }
}

static void sigint_handler(int sig)
{
    (void)sig;
    restore_terminal();
    if (g_child_pid > 0) {
        killpg(g_child_pid, SIGTERM);
        usleep(200000);
        int status;
        if (waitpid(g_child_pid, &status, WNOHANG) == 0) {
            killpg(g_child_pid, SIGKILL);
            waitpid(g_child_pid, NULL, 0);
        }
        g_child_pid = -1;
    }
    if (g_tmpdir_created) {
        nftw(g_tmpdir, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
        g_tmpdir_created = 0;
    }
    _exit(130);
}

static void raw_terminal(void)
{
    if (term_raw) return;

    if (tcgetattr(STDIN_FILENO, &orig_term) == -1)
        return;

    struct termios t = orig_term;

    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0)
        term_raw = 1;
}

static void restore_terminal(void)
{
    if (term_raw) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term);
        term_raw = 0;
    }
}

static void open_file_manager(const char *path)
{
    setsid();
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
    
    const char *fm = getenv("XDG_FILE_MANAGER");
    if (fm) {
        execlp(fm, fm, path, NULL);
    }
    execlp("xdg-open", "xdg-open", path, NULL);
    execlp("thunar", "thunar", path, NULL);
    execlp("nautilus", "nautilus", "--no-desktop", path, NULL);
    execlp("dolphin", "dolphin", path, NULL);
    _exit(1);
}

static void ensure_tmpdir_and_fm(void)
{
    if (g_tmpdir_created && g_child_pid > 0)
        return;

    if (!g_tmpdir_created) {
        strcpy(g_tmpdir, TMP_TEMPLATE);
        if (!mkdtemp(g_tmpdir)) {
            perror("mkdtemp");
            return;
        }
        g_tmpdir_created = 1;
    }

    if (g_child_pid <= 0) {
        g_child_pid = fork();
        if (g_child_pid == 0) {
            setpgid(0, 0);
            open_file_manager(g_tmpdir);
        } else if (g_child_pid < 0) {
            perror("fork");
        } else {
            setpgid(g_child_pid, g_child_pid);
            usleep(500000);
            pid_t min_pid = fork();
            if (min_pid == 0) {
                setsid();
                close(STDIN_FILENO);
                close(STDOUT_FILENO);
                close(STDERR_FILENO);
                open("/dev/null", O_RDONLY);
                open("/dev/null", O_WRONLY);
                open("/dev/null", O_WRONLY);
                execlp("xdotool", "xdotool", "search", "--class", "Thunar", "windowminimize", NULL);
                execlp("xdotool", "xdotool", "search", "--class", "Nautilus", "windowminimize", NULL);
                execlp("xdotool", "xdotool", "search", "--class", "dolphin", "windowminimize", NULL);
                                    execlp("wmctrl", "wmctrl", "-r", g_tmpdir, "-b", "add,hidden", NULL);
                _exit(0);
            }
        }
    }
}

static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) {
        perror(src);
        return 0;
    }

    FILE *out = fopen(dst, "wb");
    if (!out) {
        perror(dst);
        fclose(in);
        return 0;
    }

    char buf[BUF_SIZE];
    size_t n;
    int success = 1;
    
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            perror("fwrite");
            success = 0;
            break;
        }
    }

    if (ferror(in)) {
        perror("fread");
        success = 0;
    }

    fclose(in);
    fclose(out);
    
    if (success) {
        chmod(dst, 0444);
    } else {
        unlink(dst);
    }
    
    return success;
}

static char *unique_dest(const char *base)
{
    char *name = strdup(base);
    if (!name) return NULL;
    
    char *ext = strrchr(name, '.');
    char *path = NULL;
    int n = 1;
    int has_ext = (ext != NULL && ext != name);

    if (has_ext) {
        *ext = '\0';
        char *ext_part = ext + 1;
        asprintf(&path, "%s/%s.%s", g_tmpdir, name, ext_part);
    } else {
        asprintf(&path, "%s/%s", g_tmpdir, name);
    }

    while (path && access(path, F_OK) == 0) {
        free(path);
        if (has_ext) {
            asprintf(&path, "%s/%s_%d.%s", g_tmpdir, name, ++n, ext + 1);
        } else {
            asprintf(&path, "%s/%s_%d", g_tmpdir, name, ++n);
        }
    }

    free(name);
    return path;
}

static int has_glob(const char *s)
{
    for (; *s; s++)
        if (*s == '*' || *s == '?' || *s == '[')
            return 1;
    return 0;
}

static void reset_results(void)
{
    for (int i = 0; i < result_count; i++)
        free(results[i]);
    result_count = 0;
    selected = 0;
}

static void collect_non_recursive(const char *pattern)
{
    const char *search_dir = current_dir ? current_dir : g_root;
    DIR *d = opendir(search_dir);
    if (!d) {
        perror(search_dir);
        return;
    }

    struct dirent *de;
    while ((de = readdir(d)) && result_count < MAX_RESULTS) {
        if (de->d_name[0] == '.')
            continue;

        int ok = 1;
        if (pattern && *pattern) {
            const char *p = pattern;
            while (*p && isspace(*p)) p++;
            
            if (*p) {
                ok = has_glob(p)
                    ? fnmatch(p, de->d_name, FNM_CASEFOLD) == 0
                    : strncasecmp(de->d_name, p, strlen(p)) == 0;
            }
        }

        if (!ok)
            continue;

        char *full_path;
        if (asprintf(&full_path, "%s/%s", search_dir, de->d_name) >= 0) {
            char *abs_path = realpath(full_path, NULL);
            if (abs_path) {
                free(full_path);
                results[result_count++] = abs_path;
            } else {
                results[result_count++] = full_path;
            }
        }
    }

    closedir(d);
}

static int is_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    return 0;
}

static void list_directory(const char *dir)
{
    reset_results();
    
    if (current_dir) {
        free(current_dir);
    }
    current_dir = strdup(dir);
    
    collect_non_recursive(NULL);
}

static void navigate_up(void)
{
    if (!current_dir) {
        return;
    }
    
    char *parent = strdup(current_dir);
    if (!parent) return;
    
    char *last_slash = strrchr(parent, '/');
    
    if (last_slash && last_slash != parent) {
        *last_slash = '\0';
        list_directory(parent);
    } else if (last_slash == parent) {
        list_directory(g_root);
    } else {
        list_directory(g_root);
    }
    
    free(parent);
}

static void walk_directory(const char *dir, const char *filter_pattern)
{
    DIR *d = opendir(dir);
    if (!d) {
        return;
    }
    
    struct dirent *de;
    errno = 0;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' && 
            (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        
        char *full_path;
        size_t dir_len = strlen(dir);
        if (dir_len > 0 && dir[dir_len - 1] == '/') {
            if (asprintf(&full_path, "%.*s%s", (int)(dir_len - 1), dir, de->d_name) < 0)
                continue;
        } else {
            if (asprintf(&full_path, "%s/%s", dir, de->d_name) < 0)
                continue;
        }
        
        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                if (result_count < MAX_RESULTS) {
                    int matches = 1;
                    if (filter_pattern && *filter_pattern) {
                        const char *bn = basename(full_path);
                        const char *p = filter_pattern;
                        while (*p && isspace(*p)) p++;
                        if (*p) {
                            matches = has_glob(p)
                                ? fnmatch(p, bn, FNM_CASEFOLD) == 0
                                : strcasestr(bn, p) != NULL;
                        }
                    }
                    
                    if (matches) {
                        char *abs_path = realpath(full_path, NULL);
                        if (abs_path) {
                            results[result_count++] = abs_path;
                        } else {
                            if (full_path[0] == '/') {
                                results[result_count++] = strdup(full_path);
                            } else {
                                char *abs;
                                if (asprintf(&abs, "%s/%s", g_root, full_path) >= 0) {
                                    results[result_count++] = abs;
                                }
                            }
                        }
                    }
                }
            } else if (S_ISDIR(st.st_mode)) {
                walk_directory(full_path, filter_pattern);
            }
        }
        
        free(full_path);
    }
    
    closedir(d);
}

static void collect_recursive(const char *pattern)
{
    result_count = 0;
    
    struct stat st;
    if (stat(g_root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return;
    }
    
    size_t root_len = strlen(g_root);
    char *root_clean = (char *)g_root;
    if (root_len > 1 && g_root[root_len - 1] == '/') {
        root_clean = strdup(g_root);
        root_clean[root_len - 1] = '\0';
    }
    
    const char *filter_pattern = NULL;
    if (pattern && *pattern) {
        filter_pattern = pattern;
        while (*filter_pattern && isspace(*filter_pattern)) filter_pattern++;
        if (!*filter_pattern) filter_pattern = NULL;
    }
    
    walk_directory(root_clean, filter_pattern);
    
    if (root_clean != g_root) {
        free(root_clean);
    }
}

static void draw(const char *mode)
{
    printf("\033[2J\033[H");
    const char *dir_display = current_dir ? current_dir : g_root;
    printf("[x3] %s  (↑ ↓ select, → enter dir, ← go back, Enter copy, q quit)\n", mode);
    printf("Path: %s\n\n", dir_display);

    int start = 0;
    int end = result_count;
    int max_lines = 20;
    
    if (result_count > max_lines) {
        if (selected > max_lines / 2) {
            start = selected - max_lines / 2;
            end = start + max_lines;
            if (end > result_count) {
                end = result_count;
                start = end - max_lines;
            }
        } else {
            end = max_lines;
        }
    }

    if (start > 0)
        printf("... (%d more above)\n", start);

    for (int i = start; i < end; i++) {
        const char *marker = (i == selected) ? ">" : " ";
        const char *path = results[i];
        int is_dir = is_directory(path);
        printf("%s %s%s\n", marker, path, is_dir ? "/" : "");
    }

    if (end < result_count)
        printf("... (%d more below)\n", result_count - end);
    
    if (result_count == 0)
        printf("(no results)\n");
}

static void selector(const char *mode)
{
    raw_terminal();
    draw(mode);

    while (1) {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1)
            break;

        if (c == 'q' || c == 3) {
            restore_terminal();
            if (g_child_pid > 0) {
                killpg(g_child_pid, SIGTERM);
                usleep(200000);
                int status;
                if (waitpid(g_child_pid, &status, WNOHANG) == 0) {
                    killpg(g_child_pid, SIGKILL);
                    waitpid(g_child_pid, NULL, 0);
                }
                g_child_pid = -1;
            }
            break;
        }

        if (c == '\n' && result_count > 0) {
            if (!is_directory(results[selected])) {
                    if (!g_tmpdir_created) {
                        strcpy(g_tmpdir, TMP_TEMPLATE);
                        if (mkdtemp(g_tmpdir)) {
                            g_tmpdir_created = 1;
                        }
                    }
                    
                    if (g_tmpdir_created) {
                        char *dst = unique_dest(basename(results[selected]));
                        if (dst) {
                            if (copy_file(results[selected], dst)) {
                                printf("\n[x3] Copied -> %s\n", basename(dst));
                                
                                if (g_child_pid <= 0) {
                                    g_child_pid = fork();
                                    if (g_child_pid == 0) {
                                        setpgid(0, 0);
                                        open_file_manager(g_tmpdir);
                                    } else if (g_child_pid > 0) {
                                        setpgid(g_child_pid, g_child_pid);
                                        usleep(500000);
                                        pid_t min_pid = fork();
                                        if (min_pid == 0) {
                                            setsid();
                                            close(STDIN_FILENO);
                                            close(STDOUT_FILENO);
                                            close(STDERR_FILENO);
                                            open("/dev/null", O_RDONLY);
                                            open("/dev/null", O_WRONLY);
                                            open("/dev/null", O_WRONLY);
                                            execlp("xdotool", "xdotool", "search", "--class", "Thunar", "windowminimize", NULL);
                                            execlp("xdotool", "xdotool", "search", "--class", "Nautilus", "windowminimize", NULL);
                                            execlp("xdotool", "xdotool", "search", "--class", "dolphin", "windowminimize", NULL);
                                            execlp("wmctrl", "wmctrl", "-r", g_tmpdir, "-b", "add,hidden", NULL);
                                            _exit(0);
                                        }
                                    }
                                }
                            } else {
                                printf("\n[x3] Failed to copy %s\n", basename(results[selected]));
                            }
                            free(dst);
                            sleep(1);
                        }
                    }
                }
        }
        else if (c == 27) {
            char a, b;
            if (read(STDIN_FILENO, &a, 1) != 1) continue;
            if (a != '[') continue;
            if (read(STDIN_FILENO, &b, 1) != 1) continue;

            if (b == 'A' && selected > 0)
                selected--;
            else if (b == 'B' && selected < result_count - 1)
                selected++;
            else if (b == 'C' && result_count > 0) {
                if (is_directory(results[selected])) {
                    list_directory(results[selected]);
                    selected = 0;
                }
            }
            else if (b == 'D') {
                navigate_up();
                selected = 0;
            }
            else if (b == '5' || b == '6') {
                if (read(STDIN_FILENO, &c, 1) != 1) continue;
                if (b == '5' && c == '~' && selected > 0)
                    selected = (selected > 10) ? selected - 10 : 0;
                else if (b == '6' && c == '~' && selected < result_count - 1)
                    selected = (selected < result_count - 11) ? selected + 10 : result_count - 1;
            }
        }

        draw(mode);
    }

    restore_terminal();
}

static void interactive(void)
{
    char buf[256];

    while (1) {
        printf("\n[x3] / or // (q to exit): ");
        fflush(stdout);
        
        if (!fgets(buf, sizeof(buf), stdin))
            break;

        buf[strcspn(buf, "\n")] = 0;
        if (!strcmp(buf, "q")) {
            if (g_child_pid > 0) {
                killpg(g_child_pid, SIGTERM);
                usleep(200000);
                int status;
                if (waitpid(g_child_pid, &status, WNOHANG) == 0) {
                    killpg(g_child_pid, SIGKILL);
                    waitpid(g_child_pid, NULL, 0);
                }
                g_child_pid = -1;
            }
            break;
        }

        reset_results();
        if (current_dir) {
            free(current_dir);
            current_dir = NULL;
        }

        if (!strncmp(buf, "//", 2)) {
            char *p = buf + 2;
            while (isspace(*p)) p++;
            collect_recursive(p && *p ? p : NULL);
            if (result_count)
                selector(p && *p ? "recursive" : "recursive (all)");
            else
                printf("[x3] No matches found\n");
        }
        else if (buf[0] == '/') {
            char *p = buf + 1;
            while (isspace(*p)) p++;
            collect_non_recursive(p);
            if (result_count)
                selector(p && *p ? "local" : "local (all)");
            else
                printf("[x3] No matches found\n");
        } else if (buf[0]) {
            printf("[x3] Use / to list all, /pattern for local, or //pattern for recursive\n");
        }
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sigint_handler);
    atexit(cleanup);

    char *cwd = getcwd(NULL, 0);
    if (!cwd) {
        perror("getcwd");
        return 1;
    }
    g_root = realpath(cwd, NULL);
    if (!g_root) {
        g_root = cwd;
    } else {
        free(cwd);
    }
    if (g_root && strlen(g_root) > 1 && g_root[strlen(g_root) - 1] == '/') {
        g_root[strlen(g_root) - 1] = '\0';
    }

    if (argc == 2) {
        struct stat st;
        char *rp = realpath(argv[1], NULL);
        if (rp && stat(rp, &st) == 0 && S_ISDIR(st.st_mode)) {
            free(g_root);
            g_root = strdup(rp);

            pid_t pid = fork();
            if (pid == 0) {
                setpgid(0, 0);
                open_file_manager(g_root);
            } else if (pid > 0) {
                g_child_pid = pid;
                setpgid(pid, pid);
            }

            free(rp);
            interactive();
            return 0;
        }
        free(rp);
    }

    if (argc == 1) {
        interactive();
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        char *rp = realpath(argv[i], NULL);
        if (!rp) continue;

        struct stat st;
        if (stat(rp, &st) == 0 && S_ISREG(st.st_mode)) {
            ensure_tmpdir_and_fm();
            char *dst = unique_dest(basename(rp));
            if (dst) {
                copy_file(rp, dst);
                free(dst);
            }
        }
        free(rp);
    }

    interactive();
    return 0;
}
