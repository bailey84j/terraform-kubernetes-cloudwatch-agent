# region Kubernetes Resources
# Referencing
# https://github.com/aws-samples/amazon-cloudwatch-container-insights/blob/master/k8s-yaml-templates/quickstart/cwagent-fluentd-quickstart.yaml
# Line 10
resource "kubernetes_service_account" "this" {
  metadata {
    name      = var.name
    namespace = var.namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = var.create_iam_role ? aws_iam_role.this[0].arn : var.iam_role_arn
    }
    labels = {
      "app.kubernetes.io/name"       = "${var.name}-agent"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}
# line 191
resource "kubernetes_cluster_role" "this" {
  metadata {
    name = "${var.name}-agent-role"
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "nodes", "endpoints"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["replicasets"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = ["batch"]
    resources  = ["jobs"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = [""]
    resources  = ["nodes/proxy"]
    verbs      = ["get"]
  }
  rule {
    api_groups = [""]
    resources  = ["nodes/stats", "configmaps", "events"]
    verbs      = ["create"]
  }
  rule {
    api_groups     = [""]
    resources      = ["configmaps"]
    resource_names = ["cwagent-clusterleader"]
    verbs          = ["get", "update"]
  }



}
# Line 44
resource "kubernetes_cluster_role_binding" "this" {
  metadata {
    name = "${var.name}-agent-role-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "${var.name}-agent-role"
  }
  subject {
    kind      = "ServiceAccount"
    name      = var.name
    namespace = var.namespace
  }
}

data "template_file" "this" {
  template = file("${path.module}/templates/config.tpl")
  vars = {
    region_name  = data.aws_region.current.name
    cluster_name = data.aws_eks_cluster.target.name
  }
}

# Line 216
resource "kubernetes_config_map" "this" {
  metadata {
    labels = {
      "k8s-app" = "${var.name}-agent"
    }
    name      = "cwagentconfig"
    namespace = var.namespace
  }

  data = {
    "cwagentconfig.json" = data.template_file.this.rendered
  }

}

# Line 85
resource "kubernetes_daemonset" "this" {
  metadata {
    name      = "${var.name}-agent"
    namespace = var.namespace
  }

  spec {
    selector {
      match_labels = {
        name = "${var.name}-agent"
      }
    }

    template {
      metadata {
        labels = {
          name = "${var.name}-agent"
        }
      }

      spec {
        volume {
          name = "cwagentconfig"

          config_map {
            name = "cwagentconfig"
          }
        }

        volume {
          name = "rootfs"

          host_path {
            path = "/"
          }
        }

        volume {
          name = "dockersock"

          host_path {
            path = "/var/run/docker.sock"
          }
        }

        volume {
          name = "varlibdocker"

          host_path {
            path = "/var/lib/docker"
          }
        }

        volume {
          name = "sys"

          host_path {
            path = "/sys"
          }
        }

        volume {
          name = "devdisk"

          host_path {
            path = "/dev/disk/"
          }
        }

        container {
          name  = "${var.name}-agent"
          image = "amazon/${var.image_name}:${var.image_version}"

          env {
            name = "HOST_IP"

            value_from {
              field_ref {
                field_path = "status.hostIP"
              }
            }
          }

          env {
            name = "HOST_NAME"

            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }

          env {
            name = "K8S_NAMESPACE"

            value_from {
              field_ref {
                field_path = "metadata.namespace"
              }
            }
          }

          env {
            name  = "CI_VERSION"
            value = "k8s/${data.aws_eks_cluster.target.version}"
          }

          resources {
            limits = {
              cpu = "200m"

              memory = "200Mi"
            }

            requests = {
              cpu = "200m"

              memory = "200Mi"
            }
          }

          volume_mount {
            name       = "cwagentconfig"
            mount_path = "/etc/cwagentconfig"
          }

          volume_mount {
            name       = "rootfs"
            read_only  = true
            mount_path = "/rootfs"
          }

          volume_mount {
            name       = "dockersock"
            read_only  = true
            mount_path = "/var/run/docker.sock"
          }

          volume_mount {
            name       = "varlibdocker"
            read_only  = true
            mount_path = "/var/lib/docker"
          }

          volume_mount {
            name       = "sys"
            read_only  = true
            mount_path = "/sys"
          }

          volume_mount {
            name       = "devdisk"
            read_only  = true
            mount_path = "/dev/disk"
          }
        }

        termination_grace_period_seconds = 60
        service_account_name             = var.name
      }
    }
  }
}

# endregion Kubernetes Resources



# region aws iam role

locals {
  iam_role_name = coalesce(var.iam_role_name, "${var.eks_cluster_name}-${var.name}")
}
# to be updated
data "aws_iam_policy_document" "assume_role_policy" {
  count = var.create_iam_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    condition {
      test     = "StringEquals"
      variable = "${replace(data.aws_eks_cluster.target.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values = [
        "system:serviceaccount:${var.namespace}:${var.name}"
      ]
    }
    principals {
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.target.identity[0].oidc[0].issuer, "https://", "")}"
      ]
      type = "Federated"
    }
  }
}

resource "aws_iam_role" "this" {
  count = var.create_iam_role ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}${var.prefix_separator}" : null
  path        = var.iam_role_path
  description = var.iam_role_description

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy[0].json
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = true


  inline_policy {
    name = "DescribeEC2TagsAndVolumes"

    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:DescribeTags",
            "ec2:DescribeVolumes",
          ]
          "Resource" : "*"
        }
      ]
    })
  }

  managed_policy_arns = ["arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSAppSyncPushToCloudWatchLogs"]

  tags = merge(var.tags, var.iam_role_tags)

}

# endregion aws iam role
